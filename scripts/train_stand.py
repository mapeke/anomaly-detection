"""Переобучение трёх детекторов на трафике, записанном со стенда GNS3.

Пример (время — UTC, как в журнале атак):
  python scripts/train_stand.py \
      --normal "2026-11-02 10:00:00" "2026-11-02 11:00:00" \
      --attacks "2026-11-02 11:10:00" "2026-11-02 12:10:00" \
      --journal stand/journals/train_full.csv stand/journals/train_low.csv

- правила и Isolation Forest обучаются на первых 75 % нормального интервала,
  порог Isolation Forest — максимум оценки на последних 25 % (+2 %);
- XGBoost обучается на окнах нормального интервала и интервала атак, размеченных по журналу.
Результат: models/window_models_stand.joblib (предыдущая версия -> models/window_models_sim.joblib).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import joblib
import pandas as pd
import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.detectors import AnomalyDetector, AttackClassifier, ThresholdDetector  # noqa: E402
from nids.features import WINDOW_FEATURES, aggregate_windows  # noqa: E402
from nids.standdata import label_windows, load_flows, load_journal  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--db", default=os.getenv("DATABASE_URL", "postgresql://nids:nids@localhost:5432/nids"))
ap.add_argument("--normal", nargs=2, required=True, metavar=("START", "END"))
ap.add_argument("--attacks", nargs=2, required=True, metavar=("START", "END"))
ap.add_argument("--journal", nargs="+", required=True)
ap.add_argument("--window", type=int, default=10)
a = ap.parse_args()
W = a.window

with psycopg.connect(a.db) as conn:
    fn = load_flows(conn, *a.normal)
    fa = load_flows(conn, *a.attacks)
journal = load_journal(a.journal)
print(f"нормальный трафик: {len(fn)} потоков; интервал атак: {len(fa)} потоков; атак в журнале: {len(journal)}")
if len(fn) < 1000 or len(fa) < 100:
    sys.exit("слишком мало потоков — проверьте интервалы времени (UTC) и что loader пишет в БД")

Xn = aggregate_windows(fn, W, min_flows=3)
cut = Xn.index.get_level_values("win").min() + int(0.75 * (Xn.index.get_level_values("win").max() -
                                                             Xn.index.get_level_values("win").min()))
Xn_tr = Xn[Xn.index.get_level_values("win") <= cut]
Xn_va = Xn[Xn.index.get_level_values("win") > cut]
rules = ThresholdDetector().fit(Xn_tr[WINDOW_FEATURES])
iso = AnomalyDetector().fit(Xn_tr[WINDOW_FEATURES])
iso.threshold = float(iso.score(Xn_va).max() * 1.02)

Xa = label_windows(aggregate_windows(fa, W, min_flows=3), journal, W)
Xn_l = label_windows(Xn, journal.iloc[0:0], W)
Xall = pd.concat([Xn_l, Xa])
print("окон по классам:", Xall.attack.value_counts().to_dict())
if Xall.label.sum() == 0:
    sys.exit("ни одно окно не размечено как атака — проверьте адрес атакующего и время в журнале")
xgb = AttackClassifier("xgb", WINDOW_FEATURES).fit(Xall[WINDOW_FEATURES], Xall.attack)

out = ROOT / "models" / "window_models_stand.joblib"
backup = ROOT / "models" / "window_models_sim.joblib"
if out.exists() and not backup.exists():
    shutil.copy(out, backup)
joblib.dump({"rules": rules, "iforest": iso, "xgb": xgb, "window_s": W}, out)
summary = {"normal_flows": len(fn), "attack_flows": len(fa), "normal_windows": len(Xn),
           "labelled_windows": Xall.attack.value_counts().to_dict(),
           "rules_thresholds": {k: round(v, 2) for k, v in rules.thr.items()},
           "iforest_threshold": round(iso.threshold, 4),
           "rules_on_normal_val": int(rules.predict(Xn_va[WINDOW_FEATURES]).sum()),
           "iforest_on_normal_val": int(iso.predict(Xn_va).sum())}
(ROOT / "results" / "stand_train.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
print(f"модели сохранены: {out}; перезапустите детектор: docker compose restart detector")
