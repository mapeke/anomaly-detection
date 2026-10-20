"""Дополнительные эксперименты на оконных признаках (окна 10 с, NF-UNSW-NB15-v3):

1. чувствительность Isolation Forest к числу деревьев и объёму подвыборки (ROC-AUC на валидации);
2. чувствительность XGBoost к глубине деревьев (F1 на валидации);
3. абляция наборов признаков: 9 признаков ФТ-2 против всех 13;
4. важность оконных признаков XGBoost.
Подбор — только на валидационной части; итоговые значения выбранной конфигурации — на тесте.
Результат: results/extra.json, results/figures/extra_*.png
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.detectors import SEED  # noqa: E402
from nids.features import WINDOW_FEATURES, aggregate_windows, from_nf_v3  # noqa: E402

FIG = ROOT / "results" / "figures"
plt.rcParams.update({"font.size": 11, "figure.dpi": 150, "savefig.bbox": "tight"})
BLOCK_MIN, W = 5, 10
rng = np.random.default_rng(SEED)

raw = pd.read_parquet(ROOT / "data" / "raw" / "NF-UNSW-NB15-v3.parquet").drop_duplicates().reset_index(drop=True)
block = raw["FLOW_START_MILLISECONDS"] // (BLOCK_MIN * 60_000)
blk_att = raw.groupby(block)["Label"].max()
split_of_block = {}
for has_att in (0, 1):   # то же разбиение, что в train_eval.py
    ids = blk_att[blk_att == has_att].index.to_numpy().copy()
    rng.shuffle(ids)
    for i, b in enumerate(ids):
        split_of_block[b] = "train" if i < 0.7 * len(ids) else ("val" if i < 0.85 * len(ids) else "test")
X = aggregate_windows(from_nf_v3(raw), W, key="src")
wb = (X.index.get_level_values("win").to_numpy() * W * 1000) // (BLOCK_MIN * 60_000)
X["split"] = pd.Series(wb).map(split_of_block).to_numpy()
tr, va, te = (X[X.split == s] for s in ("train", "val", "test"))
out = {}


def iso_auc(features, n_est, ms, fit_df, eval_df):
    sc = StandardScaler()
    xf = np.log1p(fit_df.loc[fit_df.label == 0, features].clip(lower=0))
    m = IsolationForest(n_estimators=n_est, max_samples=ms, random_state=SEED, n_jobs=-1).fit(sc.fit_transform(xf))
    s = -m.score_samples(sc.transform(np.log1p(eval_df[features].clip(lower=0))))
    return roc_auc_score(eval_df.label, s)


# 1. Isolation Forest
grid = {}
for n_est in (50, 100, 200, 400):
    for ms in (256, 1024, 4096):
        grid[f"{n_est}/{ms}"] = round(iso_auc(WINDOW_FEATURES, n_est, ms, tr, va), 4)
        print("if", n_est, ms, grid[f"{n_est}/{ms}"], flush=True)
out["iforest_grid_val_auc"] = grid
fig, ax = plt.subplots(figsize=(6.5, 3.8))
for ms in (256, 1024, 4096):
    ax.plot([50, 100, 200, 400], [grid[f"{n}/{ms}"] for n in (50, 100, 200, 400)], marker="o", label=f"ψ = {ms}")
ax.set_xscale("log", base=2); ax.set_xticks([50, 100, 200, 400], ["50", "100", "200", "400"])
ax.set_xlabel("Число деревьев T"); ax.set_ylabel("ROC-AUC (валидация)"); ax.grid(alpha=.3); ax.legend()
ax.set_title("Чувствительность Isolation Forest к параметрам")
fig.savefig(FIG / "extra_iforest_grid.png"); plt.close(fig)

# 2. XGBoost: глубина
depth = {}
for d in (2, 4, 6, 8, 10):
    m = XGBClassifier(n_estimators=300, max_depth=d, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9,
                      tree_method="hist", random_state=SEED, n_jobs=-1).fit(tr[WINDOW_FEATURES], tr.label)
    depth[d] = round(f1_score(va.label, m.predict(va[WINDOW_FEATURES])), 4)
    print("xgb depth", d, depth[d], flush=True)
out["xgb_depth_val_f1"] = depth

# 3. абляция наборов признаков
FT2 = WINDOW_FEATURES[:9]
abl = {}
for name, fs in (("ФТ-2 (9 признаков)", FT2), ("все 13 признаков", WINDOW_FEATURES)):
    m = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9,
                      tree_method="hist", random_state=SEED, n_jobs=-1).fit(tr[fs], tr.label)
    abl[name] = {"xgb_test_f1": round(f1_score(te.label, m.predict(te[fs])), 4),
                 "iforest_test_auc": round(iso_auc(fs, 200, 4096, tr, te), 4)}
    print("abl", name, abl[name], flush=True)
out["feature_set_ablation"] = abl

# 4. важность оконных признаков
m = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9,
                  tree_method="hist", random_state=SEED, n_jobs=-1).fit(tr[WINDOW_FEATURES], tr.label)
imp = pd.Series(m.feature_importances_, index=WINDOW_FEATURES).sort_values()
out["window_importance"] = {k: round(float(v), 4) for k, v in imp[::-1].items()}
fig, ax = plt.subplots(figsize=(6.5, 4.5))
ax.barh(imp.index, imp.values, color="#2b6cb0")
ax.set_xlabel("Важность (gain)"); ax.set_title("XGBoost: важность оконных признаков (10 с)")
fig.savefig(FIG / "extra_window_importance.png"); plt.close(fig)

# время агрегации и вывода одного окна (для оценки задержки обработки)
t0 = time.perf_counter()
for _ in range(20):
    m.predict_proba(te[WINDOW_FEATURES])
out["xgb_infer_windows_per_s"] = int(20 * len(te) / (time.perf_counter() - t0))
(ROOT / "results" / "extra.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(out, ensure_ascii=False, indent=1))
