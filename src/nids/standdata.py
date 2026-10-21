"""Чтение записанного трафика стенда из PostgreSQL и журналов атак."""
from __future__ import annotations

import pandas as pd

FLOWS_SQL = """SELECT (extract(epoch FROM ts)*1000)::bigint AS ts, (extract(epoch FROM te)*1000)::bigint AS te,
                      host(src) AS src, host(dst) AS dst, sport, dport, proto, bytes, pkts, flags,
                      (extract(epoch FROM received_at)*1000)::bigint AS export
               FROM flows WHERE ts >= %s AND ts < %s ORDER BY received_at, id"""


def to_ms(t: str) -> int:
    """'2026-10-21T14:03:20Z' / '2026-10-21 14:03:20' (UTC) -> мс."""
    return int(pd.Timestamp(t).tz_localize("UTC").value // 10**6) if pd.Timestamp(t).tzinfo is None \
        else int(pd.Timestamp(t).value // 10**6)


def load_flows(conn, start: str, end: str) -> pd.DataFrame:
    with conn.cursor() as cur:
        cur.execute(FLOWS_SQL, (pd.Timestamp(start, tz="UTC") if pd.Timestamp(start).tzinfo is None else pd.Timestamp(start),
                                pd.Timestamp(end, tz="UTC") if pd.Timestamp(end).tzinfo is None else pd.Timestamp(end)))
        df = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
    if df.empty:
        return df
    for col in ("ts", "te", "export", "sport", "dport", "proto", "bytes", "pkts", "flags"):
        df[col] = df[col].astype("int64")
    df["dur"] = (df["te"] - df["ts"]) / 1000.0
    return df


def load_journal(paths: list[str]) -> pd.DataFrame:
    """CSV run_attacks.sh: kind,start,end,attacker,target (время UTC ISO-8601)."""
    j = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    j["start"] = j["start"].map(to_ms)
    j["end"] = j["end"].map(to_ms)
    return j.sort_values("start").reset_index(drop=True)


def label_windows(X: pd.DataFrame, journal: pd.DataFrame, window_s: int) -> pd.DataFrame:
    """Окно источника-атакующего, пересекающееся с интервалом атаки, получает метку и тип атаки."""
    X = X.copy()
    X["label"], X["attack"] = 0, "Benign"
    win = X.index.get_level_values("win").to_numpy()
    src = X.index.get_level_values("src").to_numpy()
    W = window_s * 1000
    for _, j in journal.iterrows():
        m = (src == j.attacker) & ((win + 1) * W > j.start) & (win * W < j.end)
        X.loc[m, "label"], X.loc[m, "attack"] = 1, j.kind
    return X
