"""Оценка НФТ-2 на стенде по журналу атак.

Режим по умолчанию — по таблице incidents, заполненной работающим детектором (реальная задержка
= created_at инцидента − начало атаки). Режим --offline повторно прогоняет записанные потоки через
ядро конвейера (время экспорта = received_at), если детектор во время записи работал со старыми моделями.

  python scripts/eval_stand.py --period "2026-11-03 10:00:00" "2026-11-03 11:00:00" \
                               --journal stand/journals/test.csv [--offline]
Результат: results/stand_eval.json и таблица в консоли.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.engine import DetectionEngine  # noqa: E402
from nids.standdata import load_flows, load_journal, to_ms  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--db", default=os.getenv("DATABASE_URL", "postgresql://nids:nids@localhost:5432/nids"))
ap.add_argument("--period", nargs=2, required=True, metavar=("START", "END"))
ap.add_argument("--journal", nargs="+", required=True)
ap.add_argument("--offline", action="store_true")
ap.add_argument("--models", default=str(ROOT / "models" / "window_models_stand.joblib"))
a = ap.parse_args()
t0, t1 = to_ms(a.period[0]), to_ms(a.period[1])
hours = (t1 - t0) / 3_600_000
journal = load_journal(a.journal)
journal = journal[(journal.start >= t0) & (journal.start < t1)]

with psycopg.connect(a.db) as conn:
    if a.offline:
        flows = load_flows(conn, *a.period)
        models = joblib.load(a.models)
        eng = DetectionEngine(models, window_s=models.get("window_s", 10))
        exp = flows["export"].to_numpy()
        rows, i, t = [], 0, int(exp[0])
        while t <= exp[-1] + 60_000:
            j = np.searchsorted(exp, t, side="right")
            eng.push(flows.iloc[i:j])
            for inc in eng.step(t)[1]:
                rows.append({"started": inc.start_ms, "updated": inc.end_ms, "created": t, "src": inc.src,
                             "kind": inc.kind, "confidence": inc.confidence, "detectors": ",".join(inc.detectors)})
            i, t = j, t + 5000
        inc = pd.DataFrame(rows)
    else:
        with conn.cursor() as cur:
            cur.execute("""SELECT (extract(epoch FROM started_at)*1000)::bigint, (extract(epoch FROM updated_at)*1000)::bigint,
                                  (extract(epoch FROM created_at)*1000)::bigint, host(src), kind, confidence,
                                  array_to_string(detectors, ',')
                           FROM incidents WHERE started_at >= to_timestamp(%s) AND started_at < to_timestamp(%s)""",
                        (t0 / 1000, t1 / 1000))
            inc = pd.DataFrame(cur.fetchall(), columns=["started", "updated", "created", "src", "kind",
                                                        "confidence", "detectors"])

matched, res = set(), []
for _, j in journal.iterrows():
    m = inc[(inc.src == j.attacker) & (inc.started < j.end + 60_000) & (inc.updated > j.start)] if len(inc) else inc
    if len(m):
        first = m.sort_values("created").iloc[0]
        matched |= set(m.index)
        res.append({"scenario": j.kind, "detected": True, "latency_s": round((first.created - j.start) / 1000, 1),
                    "type": first.kind, "confidence": round(float(m.confidence.max()), 3),
                    "detectors": ",".join(sorted(set(",".join(m.detectors).split(","))))})
    else:
        res.append({"scenario": j.kind, "detected": False})
fp = inc.drop(index=list(matched)) if len(inc) else inc
out = {"period": a.period, "mode": "offline" if a.offline else "online", "hours": round(hours, 2),
       "scenarios": res, "detected": sum(r["detected"] for r in res), "total": len(res),
       "false_incidents": len(fp), "fp_per_hour": round(len(fp) / hours, 2),
       "false_examples": fp.head(10).to_dict("records")}
(ROOT / "results" / "stand_eval.json").write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str),
                                                  encoding="utf-8")
print(pd.DataFrame(res).to_string(index=False))
lat = [r["latency_s"] for r in res if r["detected"]]
print(f"\nобнаружено {out['detected']} из {out['total']} (НФТ-2: ≥ 3); макс. задержка "
      f"{max(lat) if lat else '—'} с (≤ 60); ложных инцидентов {len(fp)} за {hours:.2f} ч = {out['fp_per_hour']}/ч (≤ 2)")
