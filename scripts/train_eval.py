"""Эксперименты на датасете NF-UNSW-NB15-v3: EDA, разбиение без утечки, три детектора.

Запуск:  python scripts/train_eval.py
Результаты: results/metrics.json, results/*.csv, results/figures/*.png, models/*.joblib
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (ConfusionMatrixDisplay, average_precision_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.detectors import SEED, AnomalyDetector, AttackClassifier, ThresholdDetector  # noqa: E402
from nids.features import WINDOW_FEATURES, aggregate_windows, from_nf_v3  # noqa: E402

DATA = ROOT / "data" / "raw" / "NF-UNSW-NB15-v3.parquet"
RES, FIG, MOD = ROOT / "results", ROOT / "results" / "figures", ROOT / "models"
for p in (RES, FIG, MOD):
    p.mkdir(parents=True, exist_ok=True)
BLOCK_MIN = 5          # длина временного блока для разбиения, минут
BENIGN_FRAC = 0.2      # доля нормальных потоков в обучении (балансировка классов)
rng = np.random.default_rng(SEED)
plt.rcParams.update({"font.size": 11, "figure.dpi": 150, "savefig.bbox": "tight"})
metrics: dict = {}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def binary_metrics(y, pred, score=None) -> dict:
    m = {"precision": precision_score(y, pred, zero_division=0), "recall": recall_score(y, pred),
         "f1": f1_score(y, pred), "fpr": float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))}
    if score is not None:
        m["roc_auc"] = roc_auc_score(y, score)
        m["pr_auc"] = average_precision_score(y, score)
    return {k: round(float(v), 4) for k, v in m.items()}


def best_threshold(y, score) -> float:
    p, r, t = precision_recall_curve(y, score)
    f1 = 2 * p * r / np.clip(p + r, 1e-12, None)
    return float(t[np.argmax(f1[:-1])])


def plot_cm(y, pred, labels, name, title, normalize="true"):
    cm = confusion_matrix(y, pred, labels=labels, normalize=normalize)
    fig, ax = plt.subplots(figsize=(1.0 + 0.75 * len(labels), 0.6 + 0.7 * len(labels)))
    ConfusionMatrixDisplay(cm, display_labels=labels).plot(
        ax=ax, cmap="Blues", values_format=".2f", colorbar=False, xticks_rotation=45)
    ax.set_title(title)
    ax.set_xlabel("Предсказанный класс")
    ax.set_ylabel("Истинный класс")
    fig.savefig(FIG / f"{name}.png")
    plt.close(fig)


# ---------------------------------------------------------------- 1. загрузка и EDA
log("load")
raw = pd.read_parquet(DATA)
eda = {"rows": len(raw), "columns": raw.shape[1], "duplicates": int(raw.duplicated().sum()),
       "missing": {k: int(v) for k, v in raw.isna().sum().items() if v > 0},
       "class_counts": raw["Attack"].value_counts().to_dict()}
raw = raw.drop_duplicates().reset_index(drop=True)
raw["SRC_TO_DST_SECOND_BYTES"] = raw["SRC_TO_DST_SECOND_BYTES"].fillna(0)
num = raw.select_dtypes("number").columns
eda["infinite"] = {k: int(v) for k, v in np.isinf(raw[num]).sum().items() if v > 0}
raw[num] = raw[num].replace([np.inf, -np.inf], 0)
eda["rows_after_dedup"] = len(raw)
eda["attack_share"] = round(float(raw["Label"].mean()), 4)
metrics["eda"] = eda

cc = raw["Attack"].value_counts()
fig, ax = plt.subplots(figsize=(8, 4))
ax.barh(cc.index[::-1], cc.values[::-1], color=["#2b6cb0" if i != "Benign" else "#718096" for i in cc.index[::-1]])
ax.set_xscale("log")
ax.set_xlabel("Число потоков (логарифмическая шкала)")
for i, v in enumerate(cc.values[::-1]):
    ax.text(v * 1.1, i, f"{v:,}".replace(",", " "), va="center", fontsize=9)
ax.set_title("Распределение классов NF-UNSW-NB15-v3")
fig.savefig(FIG / "eda_classes.png"); plt.close(fig)

t = pd.to_datetime(raw["FLOW_START_MILLISECONDS"], unit="ms")
per_h = raw.groupby([t.dt.floor("h"), "Label"]).size().unstack(fill_value=0)
fig, ax = plt.subplots(figsize=(9, 3.5))
xs = np.arange(len(per_h))
ax.bar(xs, per_h[0], label="Норма", color="#a0aec0")
ax.bar(xs, per_h[1], bottom=per_h[0], label="Атака", color="#c53030")
ax.set_xticks(xs[::3], [d.strftime("%d.%m %H:00") for d in per_h.index[::3]], rotation=45, ha="right")
ax.set_ylabel("Потоков в час"); ax.legend(); ax.set_title("Распределение потоков во времени")
fig.savefig(FIG / "eda_time.png"); plt.close(fig)

ttl = raw.groupby("Label")["MIN_TTL"].value_counts(normalize=True).unstack(0).fillna(0)
top = ttl.sum(axis=1).sort_values(ascending=False).index[:6]
metrics["eda"]["ttl_share"] = {int(k): {"benign": round(float(ttl.loc[k, 0]), 3),
                                        "attack": round(float(ttl.loc[k, 1]), 3)} for k in top}
metrics["eda"]["attack_src_subnets"] = raw.loc[raw.Label == 1, "IPV4_SRC_ADDR"] \
    .str.rsplit(".", n=1).str[0].value_counts().to_dict()

# ---------------------------------------------------------------- 2. разбиение по временным блокам
block = raw["FLOW_START_MILLISECONDS"] // (BLOCK_MIN * 60_000)
blk_att = raw.groupby(block)["Label"].max()
split_of_block = {}
for has_att in (0, 1):  # стратификация блоков по наличию атак
    ids = blk_att[blk_att == has_att].index.to_numpy().copy()
    rng.shuffle(ids)
    n = len(ids)
    for i, b in enumerate(ids):
        split_of_block[b] = "train" if i < 0.7 * n else ("val" if i < 0.85 * n else "test")
raw["split"] = block.map(split_of_block)
metrics["split"] = {s: {"flows": int((raw.split == s).sum()), "attack": int(raw.loc[raw.split == s, "Label"].sum()),
                        "blocks": int(sum(1 for v in split_of_block.values() if v == s))}
                    for s in ("train", "val", "test")}
log("split", metrics["split"])

# ---------------------------------------------------------------- 3. классификация отдельных потоков
DROP = ["FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS", "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
        "L4_SRC_PORT", "DNS_QUERY_ID", "Label", "Attack", "split"]
F_ALL = [c for c in raw.columns if c not in DROP]
F_NOTTL = [c for c in F_ALL if c not in ("MIN_TTL", "MAX_TTL")]
metrics["flow_features"] = {"all": F_ALL, "no_ttl": F_NOTTL}

tr = raw[raw.split == "train"]
tr = pd.concat([tr[tr.Label == 1], tr[tr.Label == 0].sample(frac=BENIGN_FRAC, random_state=SEED)])
va, te = raw[raw.split == "val"], raw[raw.split == "test"]
metrics["flow_train_balanced"] = {"rows": len(tr), "attack": int(tr.Label.sum())}


def make(kind, n_cls):
    if kind == "xgb":
        return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9,
                             colsample_bytree=0.9, tree_method="hist", random_state=SEED, n_jobs=-1,
                             eval_metric="logloss" if n_cls == 2 else "mlogloss")
    return RandomForestClassifier(n_estimators=150, min_samples_leaf=2, random_state=SEED, n_jobs=-1)


flow_bin = {}
pr_curves = {}
for fs_name, fs in (("no_ttl", F_NOTTL), ("all", F_ALL)):
    for kind in ("rf", "xgb"):
        t0 = time.time()
        m = make(kind, 2).fit(tr[fs], tr.Label)
        fit_s = time.time() - t0
        thr = best_threshold(va.Label, m.predict_proba(va[fs])[:, 1])
        t0 = time.time()
        s = m.predict_proba(te[fs])[:, 1]
        inf_s = time.time() - t0
        res = binary_metrics(te.Label.to_numpy(), (s >= thr).astype(int), s)
        res.update(threshold=round(thr, 4), fit_s=round(fit_s, 1), infer_flows_per_s=int(len(te) / inf_s))
        flow_bin[f"{kind}_{fs_name}"] = res
        log("flow bin", kind, fs_name, res)
        if fs_name == "no_ttl":
            pr_curves[kind.upper()] = precision_recall_curve(te.Label, s)[:2]
            plot_cm(te.Label, (s >= thr).astype(int), [0, 1], f"cm_flow_bin_{kind}",
                    f"{kind.upper()}: норма/атака (потоки)")
            if kind == "xgb":
                joblib.dump({"model": m, "features": fs, "threshold": thr}, MOD / "flow_xgb_binary.joblib")
                imp = pd.Series(m.feature_importances_, index=fs).sort_values(ascending=False)[:15]
                fig, ax = plt.subplots(figsize=(7, 5))
                ax.barh(imp.index[::-1], imp.values[::-1], color="#2b6cb0")
                ax.set_xlabel("Важность (gain)"); ax.set_title("XGBoost: 15 наиболее важных признаков")
                fig.savefig(FIG / "flow_importance.png"); plt.close(fig)
                metrics["flow_importance_top"] = {k: round(float(v), 4) for k, v in imp.items()}
metrics["flow_binary"] = flow_bin

# многоклассовая задача (без TTL)
mc = {}
labels = sorted(raw.Attack.unique(), key=lambda c: (c != "Benign", c))
for kind in ("rf", "xgb"):
    enc = {c: i for i, c in enumerate(labels)}
    m = make(kind, len(labels)).fit(tr[F_NOTTL], tr.Attack.map(enc))
    pred = np.array(labels)[m.predict(te[F_NOTTL])]
    rep = classification_report(te.Attack, pred, labels=labels, output_dict=True, zero_division=0)
    mc[kind] = {"macro_f1": round(rep["macro avg"]["f1-score"], 4),
                "weighted_f1": round(rep["weighted avg"]["f1-score"], 4),
                "accuracy": round(rep["accuracy"], 4) if "accuracy" in rep else None,
                "per_class": {c: {k: round(rep[c][k], 4) for k in ("precision", "recall", "f1-score", "support")}
                              for c in labels}}
    log("flow mc", kind, mc[kind]["macro_f1"])
    plot_cm(te.Attack, pred, labels, f"cm_flow_mc_{kind}", f"{kind.upper()}: многоклассовая задача (потоки)")
metrics["flow_multiclass"] = mc

fig, ax = plt.subplots(figsize=(5.5, 4.5))
for name, (p, r) in pr_curves.items():
    ax.plot(r, p, label=name)
ax.set_xlabel("Полнота (recall)"); ax.set_ylabel("Точность (precision)")
ax.set_title("PR-кривые: норма/атака (потоки, без TTL)"); ax.legend(); ax.grid(alpha=.3)
fig.savefig(FIG / "pr_flow.png"); plt.close(fig)

# ---------------------------------------------------------------- 4. оконные детекторы
flows = from_nf_v3(raw)
flows["block"] = block.to_numpy()
flows["split"] = raw["split"].to_numpy()
win_res = {}
for W in (10, 30, 60):
    t0 = time.time()
    X = aggregate_windows(flows, window_s=W, key="src")
    agg_rate = len(flows) / (time.time() - t0)
    wblock = (X.index.get_level_values("win").to_numpy() * W * 1000) // (BLOCK_MIN * 60_000)
    X["split"] = pd.Series(wblock).map(split_of_block).to_numpy()
    Xtr, Xva, Xte = (X[X.split == s] for s in ("train", "val", "test"))
    yva, yte = Xva.label.to_numpy(), Xte.label.to_numpy()
    r = {"windows": {s: int((X.split == s).sum()) for s in ("train", "val", "test")},
         "attack_windows": {s: int(X.loc[X.split == s, "label"].sum()) for s in ("train", "val", "test")},
         "agg_flows_per_s": int(agg_rate)}

    thr_det = ThresholdDetector().fit(Xtr.loc[Xtr.label == 0, WINDOW_FEATURES])
    p_thr = thr_det.predict(Xte)
    r["rules"] = binary_metrics(yte, p_thr)

    iso = AnomalyDetector().fit(Xtr.loc[Xtr.label == 0, WINDOW_FEATURES])
    iso.calibrate_f1(Xva, yva)
    s_iso = iso.score(Xte)
    r["iforest"] = binary_metrics(yte, (s_iso > iso.threshold).astype(int), s_iso)

    clf = AttackClassifier("xgb", WINDOW_FEATURES).fit(Xtr[WINDOW_FEATURES], Xtr.attack)
    proba = clf.predict_proba(Xte)
    s_xgb = 1 - proba[:, clf.classes.index("Benign")]
    p_xgb = (s_xgb >= 0.5).astype(int)
    r["xgb"] = binary_metrics(yte, p_xgb, s_xgb)
    rf = AttackClassifier("rf", WINDOW_FEATURES).fit(Xtr[WINDOW_FEATURES], Xtr.attack)
    s_rf = 1 - rf.predict_proba(Xte)[:, rf.classes.index("Benign")]
    r["rf"] = binary_metrics(yte, (s_rf >= 0.5).astype(int), s_rf)
    pred_t = clf.predict_type(Xte)
    rep = classification_report(Xte.attack, pred_t, output_dict=True, zero_division=0)
    r["xgb_multiclass_macro_f1"] = round(rep["macro avg"]["f1-score"], 4)

    # обнаружение по типам атак (доля атакующих окон, отмеченных детектором)
    per_type = {}
    for a in sorted(Xte.attack.unique()):
        if a == "Benign":
            continue
        msk = (Xte.attack == a).to_numpy()
        per_type[a] = {"n": int(msk.sum()), "rules": round(float(p_thr[msk].mean()), 3),
                       "iforest": round(float((s_iso[msk] > iso.threshold).mean()), 3),
                       "xgb": round(float(p_xgb[msk].mean()), 3)}
    r["detection_by_type"] = per_type
    win_res[f"{W}s"] = r
    log("window", W, {k: r[k] for k in ("rules", "iforest", "xgb", "rf")})

    if W == 10:
        labels_w = ["Benign"] + sorted(a for a in Xte.attack.unique() if a != "Benign")
        plot_cm(Xte.attack, pred_t, labels_w, "cm_window_mc_xgb", "XGBoost: типы атак (окна 10 с)")
        for name, p in (("rules", p_thr), ("iforest", (s_iso > iso.threshold).astype(int)), ("xgb", p_xgb)):
            plot_cm(yte, p, [0, 1], f"cm_window_{name}", {"rules": "Пороговые правила", "iforest": "Isolation Forest",
                                                           "xgb": "XGBoost"}[name] + " (окна 10 с)")
        fig, ax = plt.subplots(figsize=(6.5, 3.8))
        ax.hist(s_iso[yte == 0], bins=80, alpha=.6, density=True, label="Норма", color="#4a5568")
        ax.hist(s_iso[yte == 1], bins=80, alpha=.6, density=True, label="Атака", color="#c53030")
        ax.axvline(iso.threshold, color="k", ls="--", label="Порог")
        ax.set_xlabel("Оценка аномальности"); ax.set_ylabel("Плотность"); ax.legend()
        ax.set_title("Isolation Forest: распределение оценок (тест, окна 10 с)")
        fig.savefig(FIG / "iforest_scores.png"); plt.close(fig)
        fig, ax = plt.subplots(figsize=(5.5, 4.5))
        for name, s in (("Isolation Forest", s_iso), ("XGBoost", s_xgb), ("Random Forest", s_rf)):
            p, rr, _ = precision_recall_curve(yte, s)
            ax.plot(rr, p, label=name)
        pm = r["rules"]
        ax.scatter([pm["recall"]], [pm["precision"]], color="k", zorder=5, label="Пороговые правила")
        ax.set_xlabel("Полнота (recall)"); ax.set_ylabel("Точность (precision)"); ax.grid(alpha=.3)
        ax.set_title("PR-кривые оконных детекторов (10 с)"); ax.legend()
        fig.savefig(FIG / "pr_window.png"); plt.close(fig)
        desc = X.groupby("label")[WINDOW_FEATURES].median().T
        desc.columns = ["Норма (медиана)", "Атака (медиана)"]
        desc.round(3).to_csv(RES / "window_feature_medians.csv")
        joblib.dump({"rules": thr_det, "iforest": iso, "xgb": clf, "window_s": W}, MOD / "window_models_unsw.joblib")
        metrics["rules_thresholds_10s"] = {k: round(v, 3) for k, v in thr_det.thr.items()}
metrics["window"] = win_res

fig, ax = plt.subplots(figsize=(6.5, 3.8))
names = {"rules": "Правила", "iforest": "Isolation Forest", "rf": "Random Forest", "xgb": "XGBoost"}
xs = np.arange(3)
for i, k in enumerate(names):
    ax.bar(xs + (i - 1.5) * 0.2, [win_res[w][k]["f1"] for w in ("10s", "30s", "60s")], 0.2, label=names[k])
ax.set_xticks(xs, ["10 с", "30 с", "60 с"]); ax.set_ylabel("F1 (тест)"); ax.set_ylim(0, 1.05)
ax.set_title("F1 оконных детекторов при разной длине окна"); ax.legend(ncol=2, fontsize=9); ax.grid(axis="y", alpha=.3)
fig.savefig(FIG / "window_size_f1.png"); plt.close(fig)

(RES / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
log("done")
