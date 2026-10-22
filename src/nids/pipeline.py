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


def _py(v):
    """numpy-скаляры -> встроенные типы Python (psycopg не адаптирует float32/int64)."""
    return v.item() if hasattr(v, "item") else v


def main():
    dsn = os.getenv("DATABASE_URL", "postgresql://nids:nids@localhost:5432/nids")
    models = joblib.load(os.getenv("MODELS_PATH", "models/window_models_stand.joblib"))
    W = int(os.getenv("WINDOW_S", models.get("window_s", 10)))
    poll = float(os.getenv("POLL_S", 5))
    eng = DetectionEngine(models, window_s=W, grace_s=float(os.getenv("GRACE_S", 20)))
    tg = TelegramNotifier()
    log.info("start: window=%ss poll=%ss clock=%s telegram=%s", W, poll, os.getenv("CLOCK", "wall"), tg.enabled)
    last_id, max_ts = 0, 0
    clock = os.getenv("CLOCK", "wall")
    export_lag_ms = int(float(os.getenv("EXPORT_LAG_S", 15)) * 1000)
    with psycopg.connect(dsn, autocommit=True) as conn:
        # после (пере)запуска обрабатываются только новые записи, а не вся история таблицы
        # (иначе накопленные потоки разом дают инциденты и оповещения); FROM_START=1 — с начала
        if os.getenv("FROM_START") != "1":
            with conn.cursor() as cur:
                cur.execute("SELECT coalesce(max(id), 0) FROM flows")
                last_id = int(cur.fetchone()[0])
            log.info("начало с id > %d", last_id)
        while True:
            t0 = time.perf_counter()
            with conn.cursor() as cur:
                cur.execute(FLOW_SQL, (last_id,))
                df = pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description])
            if len(df):
                last_id = int(df["id"].max())
                df[["ts", "te"]] = df[["ts", "te"]].astype(float).astype("int64")
                for col in ("sport", "dport", "proto", "bytes", "pkts", "flags"):
                    df[col] = df[col].astype("int64")
                df["dur"] = (df["te"] - df["ts"]) / 1000.0
                eng.push(df)
                max_ts = max(max_ts, int(df["te"].max()))
            # CLOCK=wall — часы хоста (часы маршрутизаторов должны совпадать с ними);
            # CLOCK=flows — время по самим потокам: последний te + задержка экспорта
            now = int(time.time() * 1000) if clock == "wall" else max_ts + export_lag_ms
            X, incidents = eng.step(now)
            with conn.cursor() as cur:
                if len(X):
                    rows = [(int(w) * W, s, *[_py(r[c]) for c in WIN_COLS]) for (w, s), r in X.iterrows()]
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
                                 float(inc.confidence), list(inc.detectors), int(inc.windows), sent))
            if len(df):
                log.info("flows=%d windows=%d incidents=%d %.0f ms", len(df), len(X), len(incidents),
                         (time.perf_counter() - t0) * 1000)
            time.sleep(poll)


if __name__ == "__main__":
    main()
