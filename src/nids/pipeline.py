"""Сервис онлайн-обнаружения: читает новые потоки из PostgreSQL, пишет окна и инциденты.

Переменные окружения: DATABASE_URL, MODELS_PATH, WINDOW_S, POLL_S, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID.
"""
from __future__ import annotations

import logging
import os
import time

import joblib
import pandas as pd
import psycopg

from .alerts import TelegramNotifier
from .engine import DetectionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("nids.pipeline")

FLOW_SQL = """SELECT id, extract(epoch FROM ts)*1000 AS ts, extract(epoch FROM te)*1000 AS te,
                     host(src) AS src, host(dst) AS dst, sport, dport, proto, bytes, pkts, flags
              FROM flows WHERE id > %s ORDER BY id LIMIT 200000"""
WIN_COLS = ["flows", "pkts_s", "bytes_s", "uniq_dst_ip", "uniq_dst_port", "syn_only_ratio",
            "ent_dst_ip", "ent_dst_port", "mean_dur", "rules_type", "if_score", "xgb_type", "xgb_conf"]


def main():
    dsn = os.getenv("DATABASE_URL", "postgresql://nids:nids@localhost:5432/nids")
    models = joblib.load(os.getenv("MODELS_PATH", "models/window_models_stand.joblib"))
    W = int(os.getenv("WINDOW_S", models.get("window_s", 10)))
    poll = float(os.getenv("POLL_S", 5))
    eng = DetectionEngine(models, window_s=W, grace_s=float(os.getenv("GRACE_S", 20)))
    tg = TelegramNotifier()
    log.info("start: window=%ss poll=%ss telegram=%s", W, poll, tg.enabled)
    last_id = 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        while True:
            t0 = time.perf_counter()
            df = pd.read_sql(FLOW_SQL, conn, params=(last_id,))
            if len(df):
                last_id = int(df["id"].max())
                df[["ts", "te"]] = df[["ts", "te"]].astype("int64")
                df["dur"] = (df["te"] - df["ts"]) / 1000.0
                eng.push(df)
            X, incidents = eng.step(int(time.time() * 1000))
            with conn.cursor() as cur:
                if len(X):
                    rows = [(int(w) * W, s, *[r[c] for c in WIN_COLS]) for (w, s), r in X.iterrows()]
                    cur.executemany(
                        f"INSERT INTO windows (win_start, src, {', '.join(WIN_COLS)}) "
                        f"VALUES (to_timestamp(%s), %s, {', '.join(['%s'] * len(WIN_COLS))}) ON CONFLICT DO NOTHING",
                        rows)
                for inc in incidents:
                    sent = tg.send(inc)
                    cur.execute("""INSERT INTO incidents (started_at, updated_at, src, dst, kind, confidence,
                                   detectors, windows, notified)
                                   VALUES (to_timestamp(%s), to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s)""",
                                (inc.start_ms / 1000, inc.end_ms / 1000, inc.src, inc.dst, inc.kind,
                                 inc.confidence, inc.detectors, inc.windows, sent))
            if len(df):
                log.info("flows=%d windows=%d incidents=%d %.0f ms", len(df), len(X), len(incidents),
                         (time.perf_counter() - t0) * 1000)
            time.sleep(poll)


if __name__ == "__main__":
    main()
