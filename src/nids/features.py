"""Приведение записей потоков к единой схеме и оконная агрегация признаков (ФТ-2).

Одна и та же функция `aggregate_windows` используется и при обучении на датасете,
и в онлайн-конвейере, поэтому набор и смысл признаков совпадают.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Единая схема записи потока (подмножество полей NetFlow v9 / IPFIX).
FLOW_COLUMNS = ["ts", "te", "src", "dst", "sport", "dport", "proto",
                "bytes", "pkts", "flags", "dur"]

SYN = 0x02

# Признаки окна «источник × интервал». Первые девять — из ФТ-2.
WINDOW_FEATURES = [
    "flows",            # число потоков в окне
    "pkts_s",           # пакетов в секунду
    "bytes_s",          # байт в секунду
    "uniq_dst_ip",      # уникальных IP назначения
    "uniq_dst_port",    # уникальных портов назначения
    "syn_only_ratio",   # доля TCP-потоков только с флагом SYN
    "ent_dst_ip",       # энтропия Шеннона адресов назначения, бит
    "ent_dst_port",     # энтропия портов назначения, бит
    "mean_dur",         # средняя длительность потока, с
    "bytes_per_pkt",    # средний размер пакета
    "pkts_per_flow",    # пакетов на поток
    "udp_ratio",        # доля UDP-потоков
    "small_flow_ratio", # доля потоков из 1–2 пакетов
]


def from_nf_v3(df: pd.DataFrame) -> pd.DataFrame:
    """Датасет NF-*-v3 (UQ) -> единая схема потоков."""
    out = pd.DataFrame({
        "ts": df["FLOW_START_MILLISECONDS"].to_numpy(),
        "te": df["FLOW_END_MILLISECONDS"].to_numpy(),
        "src": df["IPV4_SRC_ADDR"].to_numpy(),
        "dst": df["IPV4_DST_ADDR"].to_numpy(),
        "sport": df["L4_SRC_PORT"].to_numpy(),
        "dport": df["L4_DST_PORT"].to_numpy(),
        "proto": df["PROTOCOL"].to_numpy(),
        "bytes": (df["IN_BYTES"] + df["OUT_BYTES"]).to_numpy(),
        "pkts": (df["IN_PKTS"] + df["OUT_PKTS"]).to_numpy(),
        "flags": df["TCP_FLAGS"].to_numpy(),
        "dur": df["FLOW_DURATION_MILLISECONDS"].to_numpy() / 1000.0,
    })
    for col in ("Label", "Attack"):
        if col in df:
            out[col.lower()] = df[col].to_numpy()
    return out


def from_nfdump_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Вывод `nfdump -o csv` (поля ts,te,sa,da,sp,dp,pr,flg,ipkt,ibyt,...) -> единая схема."""
    proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
    ts = pd.to_datetime(df["ts"]).astype("int64") // 10**6
    te = pd.to_datetime(df["te"]).astype("int64") // 10**6
    flags = df["flg"].astype(str).map(_nfdump_flags)
    return pd.DataFrame({
        "ts": ts, "te": te, "src": df["sa"], "dst": df["da"],
        "sport": df["sp"].astype(int), "dport": df["dp"].astype(int),
        "proto": df["pr"].map(lambda p: proto_map.get(str(p).upper(), 0)),
        "bytes": df["ibyt"].astype(int) + df.get("obyt", 0),
        "pkts": df["ipkt"].astype(int) + df.get("opkt", 0),
        "flags": flags, "dur": (te - ts) / 1000.0,
    })


def _nfdump_flags(s: str) -> int:
    # nfdump печатает флаги как строку вида "...AP.SF" (позиции C E U A P R S F)
    bits = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}
    return sum(v for k, v in bits.items() if k in s)


def _entropy(df: pd.DataFrame, keys: list[str], col: str) -> pd.Series:
    """Энтропия Шеннона распределения значений `col` внутри групп `keys` (по числу потоков)."""
    cnt = df.groupby(keys + [col], sort=False).size().rename("c").reset_index()
    tot = cnt.groupby(keys, sort=False)["c"].transform("sum")
    p = cnt["c"] / tot
    cnt["h"] = -p * np.log2(p)
    return cnt.groupby(keys, sort=False)["h"].sum()


def aggregate_windows(flows: pd.DataFrame, window_s: int = 10,
                      key: str = "src", min_flows: int = 1) -> pd.DataFrame:
    """Агрегирует потоки в окна `window_s` секунд по ключу (источник или цель).

    Возвращает таблицу с индексом (win, key) и колонками WINDOW_FEATURES; если во входе
    есть разметка (label/attack), добавляет метку окна: атака, если не менее половины
    потоков окна — атакующие; тип — самый частый тип атаки в окне.
    """
    f = flows
    win = (f["ts"].to_numpy() // (window_s * 1000)).astype(np.int64)
    d = pd.DataFrame({
        "win": win, "key": f[key].to_numpy(), "dst_ip": f["dst"].to_numpy(),
        "dport": f["dport"].to_numpy(), "bytes": f["bytes"].to_numpy(),
        "pkts": f["pkts"].to_numpy(), "dur": f["dur"].to_numpy(),
        "is_tcp": (f["proto"].to_numpy() == 6),
        "is_udp": (f["proto"].to_numpy() == 17),
        "small": (f["pkts"].to_numpy() <= 2),
    })
    d["syn_only"] = d["is_tcp"] & (f["flags"].to_numpy() == SYN)
    if key == "dst":  # для окна по цели считаем разнообразие источников
        d["dst_ip"] = f["src"].to_numpy()
    g = d.groupby(["win", "key"], sort=False)
    agg = g.agg(flows=("bytes", "size"), bytes=("bytes", "sum"), pkts=("pkts", "sum"),
                uniq_dst_ip=("dst_ip", "nunique"), uniq_dst_port=("dport", "nunique"),
                tcp=("is_tcp", "sum"), syn=("syn_only", "sum"), udp=("is_udp", "sum"),
                small=("small", "sum"), mean_dur=("dur", "mean"))
    agg["pkts_s"] = agg["pkts"] / window_s
    agg["bytes_s"] = agg["bytes"] / window_s
    agg["syn_only_ratio"] = np.where(agg["tcp"] > 0, agg["syn"] / agg["tcp"].clip(lower=1), 0.0)
    agg["udp_ratio"] = agg["udp"] / agg["flows"]
    agg["small_flow_ratio"] = agg["small"] / agg["flows"]
    agg["bytes_per_pkt"] = agg["bytes"] / agg["pkts"].clip(lower=1)
    agg["pkts_per_flow"] = agg["pkts"] / agg["flows"]
    agg["ent_dst_ip"] = _entropy(d, ["win", "key"], "dst_ip")
    agg["ent_dst_port"] = _entropy(d, ["win", "key"], "dport")
    out = agg[WINDOW_FEATURES].astype("float64")

    if "label" in f:
        d["label"] = f["label"].to_numpy()
        d["attack"] = f["attack"].to_numpy()
        frac = d.groupby(["win", "key"], sort=False)["label"].mean()
        out["label"] = (frac >= 0.5).astype(int)
        att = d[d["label"] == 1].groupby(["win", "key"], sort=False)["attack"] \
            .agg(lambda s: s.value_counts().index[0])
        out["attack"] = att.reindex(out.index).fillna("Benign")
        out.loc[out["label"] == 0, "attack"] = "Benign"
    out = out[out["flows"] >= min_flows]
    out.index.names = ["win", key]
    return out.sort_index()
