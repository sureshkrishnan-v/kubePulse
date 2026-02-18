-- KubePulse events table (ClickHouse)
-- Optimized for 1M+ inserts/sec: MergeTree, date partitioning, LZ4 compression.
CREATE TABLE IF NOT EXISTS kubepulse.events (
    timestamp       DateTime64(3, 'UTC')    CODEC(DoubleDelta, LZ4),
    event_type      LowCardinality(String)  CODEC(LZ4),
    pid             UInt32                   CODEC(T64, LZ4),
    uid             UInt32                   CODEC(T64, LZ4),
    comm            LowCardinality(String)  CODEC(LZ4),
    node            LowCardinality(String)  CODEC(LZ4),
    namespace       LowCardinality(String)  CODEC(LZ4),
    pod             String                   CODEC(LZ4),
    labels          Map(String, String)      CODEC(LZ4),
    numerics        Map(String, Float64)     CODEC(LZ4)
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (event_type, namespace, timestamp)
TTL toDateTime(timestamp) + INTERVAL 7 DAY
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 0,
    min_rows_for_wide_part = 0;

-- Materialized view: per-minute aggregates per module
CREATE MATERIALIZED VIEW IF NOT EXISTS kubepulse.events_per_minute_mv
ENGINE = SummingMergeTree()
PARTITION BY toDate(minute)
ORDER BY (event_type, namespace, minute)
TTL minute + INTERVAL 30 DAY
AS SELECT
    toStartOfMinute(timestamp) AS minute,
    event_type,
    namespace,
    node,
    count() AS cnt,
    avg(numerics['latency_sec']) AS avg_latency,
    quantile(0.99)(numerics['latency_sec']) AS p99_latency
FROM kubepulse.events
GROUP BY minute, event_type, namespace, node;
