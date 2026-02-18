// Package metrics provides Prometheus metric definitions for KubePulse.
//
// Metrics follow Prometheus naming conventions and best practices:
// - Low cardinality labels only (namespace, pod, node — no IPs/ports)
// - Histogram buckets tuned for network latency (100µs to 1s)
// - Domain label truncated to prevent cardinality explosion
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace = "kubepulse"
)

// networkLatencyBuckets are histogram buckets optimized for network latency.
// Range: 100µs → 1s, covering LAN, container-to-container, and WAN latencies.
var networkLatencyBuckets = []float64{
	0.0001, // 100µs
	0.0005, // 500µs
	0.001,  // 1ms
	0.005,  // 5ms
	0.01,   // 10ms
	0.025,  // 25ms
	0.05,   // 50ms
	0.1,    // 100ms
	0.25,   // 250ms
	0.5,    // 500ms
	1.0,    // 1s
}

// Metrics holds all Prometheus metrics for KubePulse.
type Metrics struct {
	// TCP metrics
	TCPLatency *prometheus.HistogramVec

	// DNS metrics
	DNSQueries *prometheus.CounterVec
	DNSLatency *prometheus.HistogramVec

	// Operational metrics
	EventsDropped *prometheus.CounterVec
	EventsTotal   *prometheus.CounterVec
}

// New creates and registers all KubePulse Prometheus metrics.
func New() *Metrics {
	m := &Metrics{
		TCPLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "tcp_latency_seconds",
				Help:      "TCP connection latency in seconds, measured from connect() to close().",
				Buckets:   networkLatencyBuckets,
			},
			[]string{"namespace", "pod", "node"},
		),

		DNSQueries: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "dns_queries_total",
				Help:      "Total number of DNS queries observed.",
			},
			[]string{"namespace", "pod", "domain", "node"},
		),

		DNSLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "dns_latency_seconds",
				Help:      "DNS query latency in seconds.",
				Buckets:   networkLatencyBuckets,
			},
			[]string{"namespace", "pod", "node"},
		),

		EventsDropped: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "events_dropped_total",
				Help:      "Total number of events dropped due to ring buffer overflow or processing errors.",
			},
			[]string{"type"},
		),

		EventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "events_total",
				Help:      "Total number of events processed by type.",
			},
			[]string{"type"},
		),
	}

	return m
}

// ObserveTCPLatency records a TCP connection latency observation.
func (m *Metrics) ObserveTCPLatency(namespace, pod, node string, latencySeconds float64) {
	m.TCPLatency.WithLabelValues(namespace, pod, node).Observe(latencySeconds)
	m.EventsTotal.WithLabelValues("tcp").Inc()
}

// ObserveDNSQuery records a DNS query.
func (m *Metrics) ObserveDNSQuery(namespace, pod, domain, node string) {
	m.DNSQueries.WithLabelValues(namespace, pod, domain, node).Inc()
	m.EventsTotal.WithLabelValues("dns").Inc()
}

// ObserveDNSLatency records a DNS query latency observation.
func (m *Metrics) ObserveDNSLatency(namespace, pod, node string, latencySeconds float64) {
	m.DNSLatency.WithLabelValues(namespace, pod, node).Observe(latencySeconds)
}

// IncrementDropped increments the dropped events counter for the given type.
func (m *Metrics) IncrementDropped(eventType string) {
	m.EventsDropped.WithLabelValues(eventType).Inc()
}

// TruncateDomain truncates a full domain name to its registered domain
// to keep Prometheus cardinality low.
// Examples:
//
//	"www.api.google.com" → "google.com"
//	"kubernetes.default.svc.cluster.local" → "cluster.local"
//	"example.com" → "example.com"
func TruncateDomain(domain string) string {
	if domain == "" {
		return "unknown"
	}

	// Find the last two labels (registered domain)
	labels := splitDomainLabels(domain)
	if len(labels) <= 2 {
		return domain
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// splitDomainLabels splits a domain into its labels.
func splitDomainLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}
