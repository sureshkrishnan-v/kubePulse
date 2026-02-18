// Package constants provides all named constants for KubePulse.
// Eliminates magic numbers and hardcoded values throughout the codebase.
// All tuning parameters, sizes, timeouts, and keys are defined here.
package constants

import "time"

// ─── Agent Defaults ────────────────────────────────────────────────
const (
	// DefaultMetricsAddr is the default HTTP listen address for metrics/health.
	DefaultMetricsAddr = ":9090"

	// DefaultLogLevel is the default structured logging level.
	DefaultLogLevel = "info"

	// DefaultConfigPath is the default YAML config file path.
	DefaultConfigPath = "kubepulse.yaml"

	// Version is the current agent version.
	Version = "4.0.0"
)

// ─── Environment Variable Keys ─────────────────────────────────────
const (
	EnvMetricsAddr = "KUBEPULSE_METRICS_ADDR"
	EnvNodeName    = "KUBEPULSE_NODE_NAME"
	EnvLogLevel    = "KUBEPULSE_LOG_LEVEL"
)

// ─── EventBus ──────────────────────────────────────────────────────
const (
	// DefaultEventBusBuffer is the default per-subscriber channel size.
	DefaultEventBusBuffer = 4096

	// MinEventBusBuffer is the minimum allowed event bus buffer size.
	MinEventBusBuffer = 64

	// EventPoolMapCapacity is the initial capacity for Event Label/Numeric maps.
	EventPoolMapCapacity = 4
)

// ─── Worker Pool ───────────────────────────────────────────────────
const (
	// DefaultWorkerPoolSize is the default number of worker goroutines.
	DefaultWorkerPoolSize = 4

	// MinWorkerPoolSize is the minimum allowed worker pool size.
	MinWorkerPoolSize = 1
)

// ─── Ring Buffer Sizes ─────────────────────────────────────────────
const (
	// RingBufLarge is for high-throughput probes (tcp, dns, fileio).
	RingBufLarge = 256 * 1024 // 256 KB

	// RingBufMedium is for moderate-throughput probes (retransmit, rst, exec, drop).
	RingBufMedium = 128 * 1024 // 128 KB

	// RingBufSmall is for low-throughput probes (oom).
	RingBufSmall = 64 * 1024 // 64 KB

	// DefaultRingBufferSize is the fallback ring buffer size.
	DefaultRingBufferSize = RingBufLarge
)

// ─── Sampling ──────────────────────────────────────────────────────
const (
	// DefaultSamplingRate is the default module sampling rate (1.0 = 100%).
	DefaultSamplingRate = 1.0

	// MinSamplingRate is the minimum sampling rate.
	MinSamplingRate = 0.0

	// MaxSamplingRate is the maximum sampling rate.
	MaxSamplingRate = 1.0
)

// ─── HTTP Server Timeouts ──────────────────────────────────────────
const (
	HTTPReadTimeout  = 5 * time.Second
	HTTPWriteTimeout = 10 * time.Second
	HTTPIdleTimeout  = 120 * time.Second
)

// ─── Shutdown ──────────────────────────────────────────────────────
const (
	// ShutdownTimeout is the max time allowed for graceful shutdown.
	ShutdownTimeout = 10 * time.Second

	// ExporterShutdownTimeout for HTTP server drain.
	ExporterShutdownTimeout = 5 * time.Second
)

// ─── Self-Observability ────────────────────────────────────────────
const (
	// StatsCollectInterval is how often the Prometheus exporter collects bus stats.
	StatsCollectInterval = 5 * time.Second
)

// ─── HTTP Paths ────────────────────────────────────────────────────
const (
	PathMetrics = "/metrics"
	PathHealthz = "/healthz"
	PathReadyz  = "/readyz"
)

// ─── Prometheus Metric Names ───────────────────────────────────────
const (
	MetricPrefix = "kubepulse_"

	// Network
	MetricTCPLatency     = MetricPrefix + "tcp_latency_seconds"
	MetricDNSQueries     = MetricPrefix + "dns_queries_total"
	MetricDNSLatency     = MetricPrefix + "dns_latency_seconds"
	MetricTCPRetransmits = MetricPrefix + "tcp_retransmits_total"
	MetricTCPResets      = MetricPrefix + "tcp_resets_total"
	MetricPacketDrops    = MetricPrefix + "packet_drops_total"

	// System
	MetricOOMKills      = MetricPrefix + "oom_kills_total"
	MetricProcessExecs  = MetricPrefix + "process_execs_total"
	MetricFileIOLatency = MetricPrefix + "fileio_latency_seconds"
	MetricFileIOOps     = MetricPrefix + "fileio_ops_total"

	// Self-observability
	MetricEventsProcessed = MetricPrefix + "events_processed_total"
	MetricEventsDropped   = MetricPrefix + "events_dropped_total"
	MetricBusQueueDepth   = MetricPrefix + "eventbus_queue_depth"
	MetricModuleErrors    = MetricPrefix + "module_errors_total"
)

// ─── Prometheus Label Names ────────────────────────────────────────
const (
	LabelNamespace  = "namespace"
	LabelPod        = "pod"
	LabelNode       = "node"
	LabelDomain     = "domain"
	LabelReason     = "reason"
	LabelOp         = "op"
	LabelModule     = "module"
	LabelSubscriber = "subscriber"
)

// ─── Event Label / Numeric Keys ────────────────────────────────────
// Used as keys in Event.Labels and Event.Numeric maps.
const (
	KeySrc         = "src"
	KeyDst         = "dst"
	KeyQName       = "qname"
	KeyDomain      = "domain"
	KeyFilename    = "filename"
	KeyOp          = "op"
	KeyReason      = "reason"
	KeyLatencySec  = "latency_sec"
	KeyLatencyNs   = "latency_ns"
	KeyBytes       = "bytes"
	KeyTotalVMKB   = "total_vm_kb"
	KeyOOMScoreAdj = "oom_score_adj"
)

// ─── BPF Field Sizes ───────────────────────────────────────────────
const (
	CommSize     = 16
	QNameSize    = 128
	FilenameSize = 128
)

// ─── FileIO Operations ────────────────────────────────────────────
const (
	FileOpRead  = "read"
	FileOpWrite = "write"
)

// ─── Nanosecond Conversions ────────────────────────────────────────
const (
	NsPerSecond float64 = 1e9
)

// ─── Exporter Names ───────────────────────────────────────────────
const (
	ExporterPrometheus = "prometheus"
	ExporterOTLP       = "otlp"
)

// ─── Module Names ──────────────────────────────────────────────────
const (
	ModuleTCP        = "tcp"
	ModuleDNS        = "dns"
	ModuleRetransmit = "retransmit"
	ModuleRST        = "rst"
	ModuleOOM        = "oom"
	ModuleExec       = "exec"
	ModuleFileIO     = "fileio"
	ModuleDrop       = "drop"
)

// ─── NATS ──────────────────────────────────────────────────────────
const (
	NATSDefaultURL           = "nats://localhost:4222"
	NATSStream               = "KUBEPULSE"
	NATSSubject              = "kubepulse.events"
	NATSBatchSize            = 500
	NATSFlushInterval        = 100 * time.Millisecond
	NATSMaxPending           = 65536
	NATSStreamMaxBytes int64 = 256 * 1024 * 1024 // 256 MB
	ExporterNATS             = "nats"
)

// ─── ClickHouse ────────────────────────────────────────────────────
const (
	ClickHouseDefaultDSN    = "clickhouse://kubepulse:kubepulse@localhost:9000/kubepulse"
	ClickHouseBatchSize     = 10000
	ClickHouseFlushInterval = 1 * time.Second
	ClickHouseMaxConns      = 4
)

// ─── Redis ─────────────────────────────────────────────────────────
const (
	RedisDefaultAddr   = "localhost:6379"
	RedisCacheTTL      = 5 * time.Second
	RedisPoolSize      = 10
	RedisPubSubChannel = "kubepulse:live"
)

// ─── API Server ────────────────────────────────────────────────────
const (
	APIDefaultAddr     = ":8080"
	APIRateLimit       = 10000 // req/sec per client
	APIMaxPageSize     = 1000
	APIDefaultPageSize = 100
)
