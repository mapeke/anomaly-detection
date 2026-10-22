"""Три детектора (ФТ-3): пороговые правила, модель аномалий без учителя, классификатор атак."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from .features import WINDOW_FEATURES

SEED = 42


class ThresholdDetector:
    """База для сравнения: экспертные правила по признакам окна.

    Объёмные пороги калибруются по нормальному трафику как квантиль `q`, умноженный на
    запас `margin`; структурные пороги (доля SYN, число портов) заданы экспертно.
    """

    def __init__(self, q: float = 0.999, margin: float = 1.5,
                 scan_ports: int = 25, brute_flows: int = 30, strict: bool = True):
        # strict=False — версия 1: объёмная атака только по порогу пакетов/с;
        # strict=True  — версия 2: дополнительно требуется аномальное число потоков, чтобы
        #                не срабатывать на крупные легитимные загрузки (мало потоков, большие пакеты)
        self.q, self.margin, self.strict = q, margin, strict
        self.scan_ports, self.brute_flows = scan_ports, brute_flows
        self.thr: dict[str, float] = {}

    def fit(self, X: pd.DataFrame) -> "ThresholdDetector":
        for col in ("pkts_s", "flows", "uniq_dst_ip"):
            self.thr[col] = float(X[col].quantile(self.q) * self.margin)
        # порог «много однотипных сессий к одной цели» тоже калибруется по норме: в нормальном трафике
        # абонент может делать десятки запросов к одному веб-серверу за окно
        same = X[(X["uniq_dst_port"] <= 2) & (X["uniq_dst_ip"] <= 2)]
        if len(same):
            self.brute_flows = max(self.brute_flows, float(same["flows"].quantile(self.q) * self.margin))
        self.thr["brute_flows"] = float(self.brute_flows)
        # нижняя граница порога горизонтального сканирования: в малой сети квантиль вырождается
        self.thr["uniq_dst_ip"] = max(self.thr["uniq_dst_ip"], 10.0)
        return self

    def predict_type(self, X: pd.DataFrame) -> np.ndarray:
        t = self.thr
        out = np.full(len(X), "Benign", dtype=object)
        flood = X["pkts_s"] > t["pkts_s"]
        out[flood & (X["udp_ratio"] > 0.8)] = "UDP-flood"
        out[flood & (X["syn_only_ratio"] > 0.5)] = "SYN-flood"
        volumetric = flood & (X["flows"] > t["flows"]) if self.strict else flood
        out[(out == "Benign") & volumetric] = "Volumetric"
        scan = (X["uniq_dst_port"] >= self.scan_ports) & (X["small_flow_ratio"] > 0.5)
        sweep = X["uniq_dst_ip"] > t["uniq_dst_ip"]
        out[(out == "Benign") & (scan | sweep)] = "Scan"
        brute = (X["flows"] >= self.brute_flows) & (X["uniq_dst_port"] <= 2) & \
                (X["uniq_dst_ip"] <= 2) & (X["syn_only_ratio"] < 0.5)
        out[(out == "Benign") & brute] = "Bruteforce"
        return out

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.predict_type(X) != "Benign").astype(int)


class AnomalyDetector:
    """Isolation Forest, обученный только на нормальном трафике; порог подбирается на валидации."""

    def __init__(self, n_estimators: int = 200, features: list[str] | None = None):
        self.features = features or WINDOW_FEATURES
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=n_estimators, max_samples=4096,
                                     random_state=SEED, n_jobs=-1)
        self.threshold = 0.0

    def _x(self, X: pd.DataFrame) -> np.ndarray:
        return np.log1p(X[self.features].clip(lower=0).to_numpy())

    def fit(self, X_benign: pd.DataFrame) -> "AnomalyDetector":
        self.model.fit(self.scaler.fit_transform(self._x(X_benign)))
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Чем больше значение, тем аномальнее окно."""
        return -self.model.score_samples(self.scaler.transform(self._x(X)))

    def calibrate_f1(self, X: pd.DataFrame, y: np.ndarray) -> float:
        """Порог, максимизирующий F1 на валидационной выборке."""
        from sklearn.metrics import precision_recall_curve
        p, r, thr = precision_recall_curve(y, self.score(X))
        f1 = 2 * p * r / np.clip(p + r, 1e-12, None)
        self.threshold = float(thr[np.argmax(f1[:-1])])
        return self.threshold

    def calibrate_fpr(self, X_benign: pd.DataFrame, fpr: float = 0.001) -> float:
        """Порог по допустимой доле ложных срабатываний на нормальном трафике."""
        self.threshold = float(np.quantile(self.score(X_benign), 1 - fpr))
        return self.threshold

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.score(X) > self.threshold).astype(int)


class AttackClassifier:
    """Многоклассовый классификатор (класс Benign + типы атак) на XGBoost или Random Forest."""

    def __init__(self, kind: str = "xgb", features: list[str] | None = None):
        self.kind, self.features = kind, features
        self.enc = LabelEncoder()
        if kind == "xgb":
            self.model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1,
                                       subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                                       random_state=SEED, n_jobs=-1, eval_metric="mlogloss")
        else:
            self.model = RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                                class_weight="balanced_subsample",
                                                random_state=SEED, n_jobs=-1)

    def _x(self, X: pd.DataFrame):
        return X[self.features] if self.features else X

    def fit(self, X: pd.DataFrame, y_type, sample_weight=None) -> "AttackClassifier":
        y = self.enc.fit_transform(np.asarray(y_type))
        self.model.fit(self._x(X), y, sample_weight=sample_weight)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(self._x(X))

    def predict_type(self, X: pd.DataFrame) -> np.ndarray:
        return self.enc.inverse_transform(self.predict_proba(X).argmax(1))

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.predict_type(X) != "Benign").astype(int)

    @property
    def classes(self) -> list[str]:
        return list(self.enc.classes_)
