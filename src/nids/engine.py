"""Ядро онлайн-конвейера: новые потоки -> окна -> признаки -> три детектора -> инциденты (ФТ-3, ФТ-4).

Класс не зависит от БД и мессенджера: на вход получает пачки записей потоков и текущее
время, на выход отдаёт закрытые окна и инциденты. Это позволяет один и тот же код
запускать в сервисе (pipeline.py) и в оффлайн-оценке на журнале сценариев.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np
import pandas as pd

from .features import WINDOW_FEATURES, aggregate_windows

TYPE_NAMES = {"SYN-flood", "UDP-flood", "Scan", "Bruteforce", "Volumetric"}


@dataclass
class Incident:
    start_ms: int
    end_ms: int
    src: str
    dst: str
    kind: str
    confidence: float
    detectors: list[str] = field(default_factory=list)
    windows: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionEngine:
    def __init__(self, models: dict, window_s: int = 10, grace_s: float = 20,
                 cooldown_s: float = 120, min_flows: int = 3, use=("rules", "iforest", "xgb"),
                 xgb_min_conf: float = 0.5):
        self.rules, self.iforest, self.xgb = models.get("rules"), models.get("iforest"), models.get("xgb")
        self.W, self.grace_ms, self.cooldown_ms = window_s, int(grace_s * 1000), int(cooldown_s * 1000)
        self.min_flows, self.use, self.xgb_min_conf = min_flows, set(use), xgb_min_conf
        self.buffer: list[pd.DataFrame] = []
        self.done_until = -1                         # номер последнего закрытого окна
        self.open: dict[tuple[str, str], Incident] = {}
        self.incidents: list[Incident] = []

    def push(self, flows: pd.DataFrame):
        if len(flows):
            self.buffer.append(flows)

    def step(self, now_ms: int) -> tuple[pd.DataFrame, list[Incident]]:
        """Закрывает окна, конец которых старше now - grace, и возвращает их с новыми инцидентами."""
        if not self.buffer:
            return pd.DataFrame(), []
        buf = pd.concat(self.buffer, ignore_index=True)
        last_closed = (now_ms - self.grace_ms) // (self.W * 1000) - 1
        if last_closed <= self.done_until:
            self.buffer = [buf]
            return pd.DataFrame(), []
        win = buf["ts"].to_numpy() // (self.W * 1000)
        ready = (win <= last_closed) & (win > self.done_until)
        late = win <= self.done_until                 # опоздавшие записи отбрасываются
        self.buffer = [buf[~ready & ~late]]
        self.done_until = last_closed
        part = buf[ready]
        if part.empty:
            return pd.DataFrame(), []
        X = aggregate_windows(part, self.W, key="src", min_flows=self.min_flows)
        if X.empty:
            return X, []
        top_dst = part.assign(win=win[ready]).groupby(["win", "src"])["dst"] \
            .agg(lambda s: s.value_counts().index[0])
        X = self._detect(X)
        X["top_dst"] = top_dst.reindex(X.index).to_numpy()
        return X, self._incidents(X)

    def _detect(self, X: pd.DataFrame) -> pd.DataFrame:
        F = X[WINDOW_FEATURES]
        X = X.copy()
        X["rules_type"] = self.rules.predict_type(F) if "rules" in self.use else "Benign"
        if "iforest" in self.use:
            s = self.iforest.score(F)
            X["if_score"] = s
            X["if_alarm"] = s > self.iforest.threshold
        else:
            X["if_score"], X["if_alarm"] = 0.0, False
        if "xgb" in self.use:
            p = self.xgb.predict_proba(F)
            cls = np.array(self.xgb.classes)
            X["xgb_type"] = cls[p.argmax(1)]
            X["xgb_conf"] = p.max(1)
            benign = p[:, list(cls).index("Benign")]
            X.loc[(1 - benign) < self.xgb_min_conf, "xgb_type"] = "Benign"
        else:
            X["xgb_type"], X["xgb_conf"] = "Benign", 0.0
        return X

    def _incidents(self, X: pd.DataFrame) -> list[Incident]:
        new = []
        W = self.W * 1000
        for (win, src), r in X.iterrows():
            dets = [d for d, hit in (("rules", r.rules_type != "Benign"), ("iforest", bool(r.if_alarm)),
                                     ("xgb", r.xgb_type != "Benign")) if hit]
            if not dets:
                continue
            # тип: классификатор > правила > «Аномалия»; уверенность: вероятность классификатора
            # или нормированная оценка аномальности
            if r.xgb_type != "Benign":
                kind, conf = r.xgb_type, float(r.xgb_conf)
            elif r.rules_type != "Benign":
                kind, conf = r.rules_type, 0.9
            else:
                kind = "Anomaly"
                conf = float(min(0.99, 0.5 + (r.if_score - self.iforest.threshold) * 2))
            start, end = int(win * W), int((win + 1) * W)
            key = (src, kind)
            inc = self.open.get(key)
            if inc and start - inc.end_ms <= self.cooldown_ms:   # продолжение инцидента
                inc.end_ms, inc.windows = end, inc.windows + 1
                inc.confidence = max(inc.confidence, conf)
                inc.detectors = sorted(set(inc.detectors) | set(dets))
                continue
            inc = Incident(start, end, src, str(r.top_dst), kind, round(conf, 3), dets)
            self.open[key] = inc
            self.incidents.append(inc)
            new.append(inc)
        return new
