"""Оценка онлайн-конвейера на имитационной модели стенда (НФТ-2, НФТ-3).

1. Обучение: правила и Isolation Forest — на 1 ч нормального трафика (seed 1), порог IF —
   на отдельных 30 мин нормы (seed 2); классификатор — на размеченном прогоне сценариев (seed 3).
2. Тест (seed 4): 1 ч фона + 4 сценария; конвейер работает в режиме «реального времени»
   с шагом 5 с, учитываются задержки экспорта NetFlow (inactive timeout 15 с).
3. Ложные срабатывания: отдельный 1 ч чистого фона (seed 5).
4. Устойчивость: сценарии пониженной интенсивности (×0.2) и медленное сканирование.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nids.detectors import AnomalyDetector, AttackClassifier, ThresholdDetector  # noqa: E402
from nids.engine import DetectionEngine  # noqa: E402
from nids.features import WINDOW_FEATURES, aggregate_windows  # noqa: E402
from nids.simulator import IspTrafficModel, Scenario, default_scenarios  # noqa: E402

RES, FIG, MOD = ROOT / "results", ROOT / "results" / "figures", ROOT / "models"
W, STEP_S = 10, 5
plt.rcParams.update({"font.size": 11, "figure.dpi": 150, "savefig.bbox": "tight"})
out: dict = {}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def label_windows(X: pd.DataFrame, journal: pd.DataFrame) -> pd.DataFrame:
    X = X.copy()
    X["label"], X["attack"] = 0, "Benign"
    win = X.index.get_level_values("win").to_numpy()
    src = X.index.get_level_values("src").to_numpy()
    for _, j in journal.iterrows():
        m = (src == j.attacker) & ((win + 1) * W * 1000 > j.start) & (win * W * 1000 < j.end)
        X.loc[m, "label"], X.loc[m, "attack"] = 1, j.kind
    return X


# ---------------------------------------------------------------- 1. обучение
log("train")
f_norm, _ = IspTrafficModel(seed=1).run(3600, [])
Xn = aggregate_windows(f_norm, W, min_flows=3)
f_val, _ = IspTrafficModel(seed=2).run(1800, [])
Xv = aggregate_windows(f_val, W, min_flows=3)
rules = ThresholdDetector().fit(Xn[WINDOW_FEATURES])
iso = AnomalyDetector().fit(Xn[WINDOW_FEATURES])
iso.threshold = float(iso.score(Xv).max() * 1.02)   # ни одного срабатывания на валидационной норме
sc_train = default_scenarios(offset_s=300, gap_s=420, dur_s=120, intensity=1.0) + \
    [Scenario(s.kind, s.start_s + 1800, s.dur_s, s.rate * 0.25) for s in default_scenarios(300, 420, 120)]
f_tr, j_tr = IspTrafficModel(seed=3).run(3600, sc_train)
Xtr = label_windows(aggregate_windows(f_tr, W, min_flows=3), j_tr)
xgb = AttackClassifier("xgb", WINDOW_FEATURES).fit(Xtr[WINDOW_FEATURES], Xtr.attack)
models = {"rules": rules, "iforest": iso, "xgb": xgb}
joblib.dump({**models, "window_s": W}, MOD / "window_models_stand.joblib")
out["train"] = {"normal_windows": len(Xn), "labelled_windows": len(Xtr),
                "attack_windows": int(Xtr.label.sum()), "iforest_threshold": round(iso.threshold, 4),
                "rules_thresholds": {k: round(v, 2) for k, v in rules.thr.items()}}
log(out["train"])


# ---------------------------------------------------------------- 2. прогон в «реальном времени»
def run_online(flows: pd.DataFrame, use=("rules", "iforest", "xgb")):
    eng = DetectionEngine(models, window_s=W, grace_s=20, use=use)
    exp = flows["export"].to_numpy()
    t, t_end = int(exp[0]), int(exp[-1]) + 60_000
    i, proc, emitted = 0, 0.0, []
    while t <= t_end:
        j = np.searchsorted(exp, t, side="right")
        c0 = time.perf_counter()
        eng.push(flows.iloc[i:j])
        _, new = eng.step(t)
        proc += time.perf_counter() - c0
        emitted += [(t, inc) for inc in new]
        i, t = j, t + STEP_S * 1000
    return emitted, proc


def score(emitted, journal, hours):
    rows, matched = [], set()
    for _, j in journal.iterrows():
        hits = [(t, inc) for t, inc in emitted
                if inc.src == j.attacker and inc.start_ms < j.end + 60_000 and inc.end_ms > j.start]
        if hits:
            t, inc = min(hits, key=lambda h: h[0])
            matched |= {id(h[1]) for h in hits}
            rows.append({"scenario": j.kind, "rate": j.rate, "detected": True,
                         "latency_s": round((t - j.start) / 1000, 1), "type": inc.kind,
                         "detectors": ",".join(sorted({d for _, h in hits for d in h.detectors})),
                         "confidence": max(h.confidence for _, h in hits)})
        else:
            rows.append({"scenario": j.kind, "rate": j.rate, "detected": False})
    fp = [inc for _, inc in emitted if id(inc) not in matched]
    return rows, len(fp), round(len(fp) / hours, 2), fp


log("test")
f_te, j_te = IspTrafficModel(seed=4).run(3600, default_scenarios())
res = {}
for use in (("rules",), ("iforest",), ("xgb",), ("rules", "iforest", "xgb")):
    emitted, proc = run_online(f_te, use)
    rows, nfp, fph, fp = score(emitted, j_te, 1.0)
    name = "+".join(use)
    res[name] = {"scenarios": rows, "false_incidents": nfp, "fp_per_hour": fph,
                 "detected": int(sum(r["detected"] for r in rows)),
                 "throughput_flows_s": int(len(f_te) / proc), "flows": len(f_te),
                 "fp_examples": [i.to_dict() for i in fp[:5]]}
    log(name, res[name]["detected"], "fp", nfp, "thr", res[name]["throughput_flows_s"])
rules_v1 = ThresholdDetector(strict=False).fit(Xn[WINDOW_FEATURES])
models_v2, models = models, {**models, "rules": rules_v1}
emitted, proc = run_online(f_te, ("rules",))
rows, nfp, fph, fp = score(emitted, j_te, 1.0)
res["rules_v1"] = {"scenarios": rows, "false_incidents": nfp, "fp_per_hour": fph,
                   "detected": int(sum(r["detected"] for r in rows)), "fp_examples": [i.to_dict() for i in fp[:5]]}
models = models_v2
log("rules_v1", res["rules_v1"]["detected"], "fp", nfp)
out["test"] = res
out["test_flows_per_s_offered"] = round(len(f_te) / 3600, 1)

log("clean background")
f_bg, _ = IspTrafficModel(seed=5).run(3600, [])
emitted, proc = run_online(f_bg)
out["background_1h"] = {"flows": len(f_bg), "false_incidents": len(emitted),
                        "examples": [i.to_dict() for _, i in emitted[:5]],
                        "throughput_flows_s": int(len(f_bg) / proc)}

log("low intensity")
low = default_scenarios(intensity=0.2) + [Scenario("Scan", 3300, 240, 3.0)]  # -T2-подобное сканирование
f_lo, j_lo = IspTrafficModel(seed=6).run(3600 + 300, low)
emitted, _ = run_online(f_lo)
rows, nfp, fph, _ = score(emitted, j_lo, 1.08)
out["low_intensity"] = {"scenarios": rows, "false_incidents": nfp}

# ---------------------------------------------------------------- 3. производительность ядра
log("throughput")
big, _ = IspTrafficModel(n_subscribers=600, seed=7).run(600, default_scenarios(60, 120, 60))
eng = DetectionEngine(models, window_s=W)
c0 = time.perf_counter()
eng.push(big)
eng.step(int(big["export"].max()) + 120_000)
dt = time.perf_counter() - c0
out["batch_throughput"] = {"flows": len(big), "seconds": round(dt, 2), "flows_per_s": int(len(big) / dt)}

# ---------------------------------------------------------------- 4. график таймлайна
f = f_te
sec = (f["ts"] - f["ts"].min()) // 1000
pps = f.groupby(sec)["pkts"].sum()
fig, ax = plt.subplots(figsize=(10, 3.6))
ax.plot(pps.index / 60, pps.rolling(10).mean(), color="#4a5568", lw=0.8)
colors = {"SYN-flood": "#c53030", "UDP-flood": "#dd6b20", "Scan": "#2b6cb0", "Bruteforce": "#6b46c1"}
t0 = f["ts"].min()
for _, j in j_te.iterrows():
    ax.axvspan((j.start - t0) / 60000, (j.end - t0) / 60000, color=colors[j.kind], alpha=.15)
    ax.text((j.start - t0) / 60000, ax.get_ylim()[1] * 0.92, j.kind, fontsize=8, color=colors[j.kind])
for r in res["rules+iforest+xgb"]["scenarios"]:
    if r.get("detected"):
        js = j_te[j_te.kind == r["scenario"]].iloc[0]
        x = (js.start - t0) / 60000 + r["latency_s"] / 60
        ax.axvline(x, color=colors[r["scenario"]], ls="--", lw=1)
ax.set_xlabel("Время от начала записи, мин"); ax.set_ylabel("Пакетов/с (скольз. среднее 10 с)")
ax.set_yscale("log")
ax.set_title("Тестовый прогон: фон + 4 сценария (заливка — атака, пунктир — оповещение)")
fig.savefig(FIG / "scenario_timeline.png"); plt.close(fig)

(RES / "scenarios.json").write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
log("done")
