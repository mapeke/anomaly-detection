"""Распределение задержки обнаружения при случайном моменте начала атаки относительно границы окна.

Для каждого типа атаки — 10 коротких прогонов (10 мин фона + атака 3 мин в случайный момент),
полная конфигурация детекторов. Результат: results/latency.json, results/figures/latency.png
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.engine import DetectionEngine  # noqa: E402
from nids.simulator import IspTrafficModel, Scenario  # noqa: E402

models = joblib.load(ROOT / "models" / "window_models_stand.joblib")
W, STEP = 10, 5
rates = {"SYN-flood": 1500, "UDP-flood": 1500, "Scan": 250, "Bruteforce": 6}
rng = np.random.default_rng(2026)
out = {}
for kind, rate in rates.items():
    lat = []
    for k in range(10):
        start = float(rng.uniform(240, 300))
        f, j = IspTrafficModel(seed=100 + k).run(600, [Scenario(kind, start, 180, rate)])
        eng = DetectionEngine(models, window_s=W)
        exp = f["export"].to_numpy()
        t, i, first = int(exp[0]), 0, None
        while t <= exp[-1] + 60_000 and first is None:
            jj = np.searchsorted(exp, t, side="right")
            eng.push(f.iloc[i:jj])
            _, new = eng.step(t)
            hit = [n for n in new if n.src == j.attacker[0]]
            if hit:
                first = t
            i, t = jj, t + STEP * 1000
        lat.append(None if first is None else round((first - j.start[0]) / 1000, 1))
    vals = [v for v in lat if v is not None]
    out[kind] = {"latencies": lat, "detected": len(vals), "min": min(vals), "max": max(vals),
                 "mean": round(float(np.mean(vals)), 1)}
    print(kind, out[kind])

(ROOT / "results" / "latency.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
fig, ax = plt.subplots(figsize=(6.5, 3.5))
ax.boxplot([[v for v in out[k]["latencies"] if v is not None] for k in rates], tick_labels=list(rates))
ax.axhline(60, color="#c53030", ls="--", label="Требование НФТ-2 (60 с)")
ax.set_ylabel("Задержка обнаружения, с"); ax.set_ylim(0, 70); ax.legend(loc="lower right")
ax.set_title("Задержка обнаружения при случайном начале атаки (10 прогонов)")
ax.grid(axis="y", alpha=.3)
fig.savefig(ROOT / "results" / "figures" / "latency.png", dpi=150, bbox_inches="tight")
