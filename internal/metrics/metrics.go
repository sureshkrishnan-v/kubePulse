// Package metrics defines Prometheus metrics for KubePulse.
// All metrics use the "kubepulse_" prefix for clean namespace isolation.
package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric instruments for KubePulse.
type Metrics struct {
	// --- Network ---
	TCPLatency  *prometheus.HistogramVec
	DNSQueries  *prometheus.CounterVec
	DNSLatency  *prometheus.HistogramVec
	Retransmits *prometheus.CounterVec
	TCPResets   *prometheus.CounterVec
	PacketDrops *prometheus.CounterVec

	// --- System ---
	OOMKills      *prometheus.CounterVec
	ProcessExecs  *prometheus.CounterVec
	FileIOLatency *prometheus.HistogramVec
	FileIOOps     *prometheus.CounterVec

	// --- Internal ---
	EventsTotal   *prometheus.CounterVec
	EventsDropped *prometheus.CounterVec
}

// New creates and registers all Prometheus metrics.
func New() *Metrics {
	// Network-tuned histogram buckets
	networkBuckets := []float64{
		0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
		0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
	}

	// Storage I/O buckets: 1ms to 10s
	ioBuckets := []float64{
		0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
		0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
	}

	return &Metrics{
		// --- Network Metrics ---
		TCPLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_tcp_latency_seconds",
			Help:    "TCP connection latency measured from connect to close.",
			Buckets: networkBuckets,
		}, []string{"namespace", "pod", "node"}),

		DNSQueries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_dns_queries_total",
			Help: "Total DNS queries observed.",
		}, []string{"namespace", "pod", "domain", "node"}),

		DNSLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_dns_latency_seconds",
			Help:    "DNS query latency.",
			Buckets: networkBuckets,
		}, []string{"namespace", "pod", "node"}),

		Retransmits: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_tcp_retransmits_total",
			Help: "Total TCP packet retransmissions (packet loss indicator).",
		}, []string{"namespace", "pod", "node"}),

		TCPResets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_tcp_resets_total",
			Help: "Total TCP connection resets sent.",
		}, []string{"namespace", "pod", "node"}),

		PacketDrops: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_packet_drops_total",
			Help: "Total packets dropped by kernel with drop reason.",
		}, []string{"reason", "node"}),

		// --- System Metrics ---
		OOMKills: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_oom_kills_total",
			Help: "Total OOM kill events.",
		}, []string{"namespace", "pod", "node"}),

		ProcessExecs: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_process_execs_total",
			Help: "Total process executions in containers.",
		}, []string{"namespace", "pod", "node"}),

		FileIOLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_fileio_latency_seconds",
			Help:    "File I/O (vfs_read/vfs_write) latency.",
			Buckets: ioBuckets,
		}, []string{"namespace", "pod", "op", "node"}),

		FileIOOps: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_fileio_ops_total",
			Help: "Total slow file I/O operations (>1ms).",
		}, []string{"namespace", "pod", "op", "node"}),

		// --- Internal Metrics ---
		EventsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_events_total",
			Help: "Total events processed by type.",
		}, []string{"type"}),

		EventsDropped: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_events_dropped_total",
			Help: "Total events dropped due to ring buffer overflow.",
		}, []string{"type"}),
	}
}

// --- Observe Methods ---

func (m *Metrics) ObserveTCPLatency(ns, pod, node string, latencySec float64) {
	m.TCPLatency.WithLabelValues(ns, pod, node).Observe(latencySec)
	m.EventsTotal.WithLabelValues("tcp").Inc()
}

func (m *Metrics) ObserveDNSQuery(ns, pod, domain, node string) {
	m.DNSQueries.WithLabelValues(ns, pod, domain, node).Inc()
	m.EventsTotal.WithLabelValues("dns").Inc()
}

func (m *Metrics) ObserveDNSLatency(ns, pod, node string, latencySec float64) {
	m.DNSLatency.WithLabelValues(ns, pod, node).Observe(latencySec)
}

func (m *Metrics) ObserveRetransmit(ns, pod, node string) {
	m.Retransmits.WithLabelValues(ns, pod, node).Inc()
	m.EventsTotal.WithLabelValues("retransmit").Inc()
}

func (m *Metrics) ObserveReset(ns, pod, node string) {
	m.TCPResets.WithLabelValues(ns, pod, node).Inc()
	m.EventsTotal.WithLabelValues("rst").Inc()
}

func (m *Metrics) ObserveOOMKill(ns, pod, node string) {
	m.OOMKills.WithLabelValues(ns, pod, node).Inc()
	m.EventsTotal.WithLabelValues("oom").Inc()
}

func (m *Metrics) ObserveExec(ns, pod, node string) {
	m.ProcessExecs.WithLabelValues(ns, pod, node).Inc()
	m.EventsTotal.WithLabelValues("exec").Inc()
}

func (m *Metrics) ObserveFileIO(ns, pod, op, node string, latencySec float64) {
	m.FileIOLatency.WithLabelValues(ns, pod, op, node).Observe(latencySec)
	m.FileIOOps.WithLabelValues(ns, pod, op, node).Inc()
	m.EventsTotal.WithLabelValues("fileio").Inc()
}

func (m *Metrics) ObservePacketDrop(reason, node string) {
	m.PacketDrops.WithLabelValues(reason, node).Inc()
	m.EventsTotal.WithLabelValues("drop").Inc()
}

// --- Domain Truncation ---

// TruncateDomain reduces a fully qualified domain name to its registered domain
// (last 2 labels) to prevent Prometheus label cardinality explosion.
func TruncateDomain(domain string) string {
	if domain == "" {
		return "unknown"
	}
	labels := splitDomainLabels(domain)
	if len(labels) <= 2 {
		return domain
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

func splitDomainLabels(domain string) []string {
	return strings.Split(strings.TrimSuffix(domain, "."), ".")
}
