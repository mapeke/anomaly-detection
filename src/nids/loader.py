"""Загрузчик потоков: файлы nfcapd -> nfdump CSV -> таблица flows (ФТ-1).

nfcapd ротирует файлы каждые ROTATE_S секунд (nfcapd -t 10); загрузчик забирает закрытые
файлы nfcapd.YYYYMMDDhhmm..., вызывает `nfdump -r <file> -o csv` и пишет записи в PostgreSQL.
Для отладки без стенда можно воспроизвести поток из имитационной модели: `--replay`.
"""
from __future__ import annotations

import argparse
import io
import logging
import os
import subprocess
import time
from pathlib import Path

import pandas as pd
import psycopg

from .features import from_nfdump_csv

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("nids.loader")
COLS = ["ts", "te", "src", "dst", "sport", "dport", "proto", "bytes", "pkts", "flags"]


def insert(conn, df: pd.DataFrame, exporter: str | None = None):
    buf = io.StringIO()
    out = df[COLS].copy()
    out["ts"] = pd.to_datetime(out["ts"], unit="ms", utc=True)
    out["te"] = pd.to_datetime(out["te"], unit="ms", utc=True)
    out.to_csv(buf, index=False, header=False)
    buf.seek(0)
    with conn.cursor() as cur:
        with cur.copy(f"COPY flows ({', '.join(COLS)}) FROM STDIN WITH (FORMAT csv)") as cp:
            cp.write(buf.read())


def watch(conn, flow_dir: Path, poll: float):
    seen: set[str] = set()
    while True:
        for f in sorted(flow_dir.rglob("nfcapd.2*")):     # nfcapd.current.* ещё пишется
            if f.name in seen:
                continue
            res = subprocess.run(["nfdump", "-r", str(f), "-o", "csv", "-q"], capture_output=True, text=True)
            if res.returncode != 0 or not res.stdout.strip():
                seen.add(f.name)
                continue
            raw = pd.read_csv(io.StringIO(res.stdout), header=None, names=_NFDUMP_FIELDS, usecols=range(15))
            df = from_nfdump_csv(raw)
            insert(conn, df)
            seen.add(f.name)
            log.info("%s: %d flows", f.name, len(df))
        time.sleep(poll)


# порядок первых полей `nfdump -o csv` (nfdump 1.7)
_NFDUMP_FIELDS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "fwd", "stos",
                  "ipkt", "ibyt", "opkt", "obyt"]


def replay(conn, speed: float, seed: int):
    """Воспроизводит в БД прогон имитационной модели (фон + 4 сценария) в реальном времени."""
    from .simulator import IspTrafficModel, default_scenarios
    t0 = int(time.time() * 1000)
    flows, journal = IspTrafficModel(seed=seed).run(3600, default_scenarios(offset_s=120, gap_s=300, dur_s=90),
                                                    t0_ms=t0)
    log.info("replay: %d flows, journal:\n%s", len(flows), journal.to_string())
    exp = flows["export"].to_numpy()
    i = 0
    while i < len(flows):
        now = t0 + (time.time() * 1000 - t0) * speed
        j = exp.searchsorted(now, side="right")
        if j > i:
            insert(conn, flows.iloc[i:j])
            i = j
        time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.getenv("FLOW_DIR", "/data/nfcapd"))
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    dsn = os.getenv("DATABASE_URL", "postgresql://nids:nids@localhost:5432/nids")
    for _ in range(30):
        try:
            conn = psycopg.connect(dsn, autocommit=True)
            break
        except psycopg.OperationalError:
            time.sleep(2)
    if a.replay or os.getenv("REPLAY") == "1":
        replay(conn, a.speed, a.seed)
    else:
        watch(conn, Path(a.dir), 2.0)


if __name__ == "__main__":
    main()
