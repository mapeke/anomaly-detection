-- Схема БД прототипа: потоки, окна, инциденты (PostgreSQL 16)

CREATE TABLE IF NOT EXISTS flows (
    id          BIGSERIAL PRIMARY KEY,
    exporter    INET,                       -- маршрутизатор-экспортёр
    ts          TIMESTAMPTZ NOT NULL,       -- начало потока
    te          TIMESTAMPTZ NOT NULL,       -- конец потока
    src         INET NOT NULL,
    dst         INET NOT NULL,
    sport       INTEGER,
    dport       INTEGER,
    proto       SMALLINT,
    bytes       BIGINT,
    pkts        BIGINT,
    flags       SMALLINT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS flows_ts_idx ON flows (ts);
CREATE INDEX IF NOT EXISTS flows_received_idx ON flows (id, received_at);

CREATE TABLE IF NOT EXISTS windows (
    win_start      TIMESTAMPTZ NOT NULL,
    src            INET NOT NULL,
    flows          INTEGER,
    pkts_s         DOUBLE PRECISION,
    bytes_s        DOUBLE PRECISION,
    uniq_dst_ip    INTEGER,
    uniq_dst_port  INTEGER,
    syn_only_ratio DOUBLE PRECISION,
    ent_dst_ip     DOUBLE PRECISION,
    ent_dst_port   DOUBLE PRECISION,
    mean_dur       DOUBLE PRECISION,
    rules_type     TEXT,
    if_score       DOUBLE PRECISION,
    xgb_type       TEXT,
    xgb_conf       DOUBLE PRECISION,
    PRIMARY KEY (win_start, src)
);

CREATE TABLE IF NOT EXISTS incidents (
    id          BIGSERIAL PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    src         INET NOT NULL,
    dst         INET,
    kind        TEXT NOT NULL,              -- SYN-flood | UDP-flood | Scan | Bruteforce | Volumetric | Anomaly
    confidence  REAL,
    detectors   TEXT[],
    windows     INTEGER DEFAULT 1,
    notified    BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incidents_started_idx ON incidents (started_at DESC);

-- Сводка трафика по секундам для дашборда
CREATE OR REPLACE VIEW traffic_per_10s AS
SELECT time_bucket, sum(pkts) / 10.0 AS pps, sum(bytes) * 8 / 10.0 AS bps, count(*) AS flows
FROM (SELECT to_timestamp(floor(extract(epoch FROM ts) / 10) * 10) AS time_bucket, pkts, bytes FROM flows) t
GROUP BY time_bucket;
