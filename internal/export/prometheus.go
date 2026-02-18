package export

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/event"
)

// Prometheus is an exporter that consumes events from the EventBus
// and updates Prometheus metrics.
type Prometheus struct {
	addr   string
	logger *zap.Logger
	bus    *event.Bus
	events <-chan *event.Event
	server *http.Server
	ready  atomic.Bool

	// Metrics — organized by category
	tcpLatency    *prometheus.HistogramVec
	dnsQueries    *prometheus.CounterVec
	dnsLatency    *prometheus.HistogramVec
	retransmits   *prometheus.CounterVec
	tcpResets     *prometheus.CounterVec
	packetDrops   *prometheus.CounterVec
	oomKills      *prometheus.CounterVec
	processExecs  *prometheus.CounterVec
	fileIOLatency *prometheus.HistogramVec
	fileIOOps     *prometheus.CounterVec

	// Self-observability
	eventsProcessed *prometheus.CounterVec
	eventsDropped   *prometheus.CounterVec
	busQueueDepth   *prometheus.GaugeVec
	moduleErrors    *prometheus.CounterVec
}

// NewPrometheus creates a Prometheus exporter.
func NewPrometheus(addr string, bus *event.Bus, logger *zap.Logger) *Prometheus {
	networkBuckets := []float64{
		0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
		0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
	}
	ioBuckets := []float64{
		0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
		0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
	}

	p := &Prometheus{
		addr:   addr,
		logger: logger,
		bus:    bus,

		// --- Network ---
		tcpLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_tcp_latency_seconds",
			Help:    "TCP connection latency.",
			Buckets: networkBuckets,
		}, []string{"namespace", "pod", "node"}),

		dnsQueries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_dns_queries_total",
			Help: "Total DNS queries observed.",
		}, []string{"namespace", "pod", "domain", "node"}),

		dnsLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_dns_latency_seconds",
			Help:    "DNS query latency.",
			Buckets: networkBuckets,
		}, []string{"namespace", "pod", "node"}),

		retransmits: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_tcp_retransmits_total",
			Help: "Total TCP retransmissions.",
		}, []string{"namespace", "pod", "node"}),

		tcpResets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_tcp_resets_total",
			Help: "Total TCP connection resets.",
		}, []string{"namespace", "pod", "node"}),

		packetDrops: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_packet_drops_total",
			Help: "Total packets dropped by kernel.",
		}, []string{"reason", "node"}),

		// --- System ---
		oomKills: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_oom_kills_total",
			Help: "Total OOM kill events.",
		}, []string{"namespace", "pod", "node"}),

		processExecs: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_process_execs_total",
			Help: "Total process executions.",
		}, []string{"namespace", "pod", "node"}),

		fileIOLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubepulse_fileio_latency_seconds",
			Help:    "File I/O latency.",
			Buckets: ioBuckets,
		}, []string{"namespace", "pod", "op", "node"}),

		fileIOOps: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_fileio_ops_total",
			Help: "Total slow file I/O operations.",
		}, []string{"namespace", "pod", "op", "node"}),

		// --- Self-Observability ---
		eventsProcessed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_events_processed_total",
			Help: "Total events processed by exporter.",
		}, []string{"module"}),

		eventsDropped: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_events_dropped_total",
			Help: "Total events dropped due to backpressure.",
		}, []string{"subscriber"}),

		busQueueDepth: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kubepulse_eventbus_queue_depth",
			Help: "Current event bus queue depth per subscriber.",
		}, []string{"subscriber"}),

		moduleErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kubepulse_module_errors_total",
			Help: "Total errors by module.",
		}, []string{"module"}),
	}

	// Subscribe to event bus
	p.events = bus.Subscribe("prometheus")

	return p
}

func (p *Prometheus) Name() string { return "prometheus" }

func (p *Prometheus) Start(ctx context.Context) error {
	// Start HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if p.ready.Load() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ready\n"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready\n"))
		}
	})

	p.server = &http.Server{
		Addr:         p.addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in background
	go func() {
		p.logger.Info("Prometheus exporter listening",
			zap.String("addr", p.addr),
			zap.String("path", "/metrics"))
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Error("Prometheus HTTP server error", zap.Error(err))
		}
	}()

	// Start self-observability stats collector
	go p.collectBusStats(ctx)

	p.ready.Store(true)

	// Main event consumption loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-p.events:
			if !ok {
				return nil // bus closed
			}
			p.processEvent(evt)
		}
	}
}

func (p *Prometheus) Stop(ctx context.Context) error {
	p.ready.Store(false)
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

// SetReady marks the exporter as ready for readiness probes.
func (p *Prometheus) SetReady() {
	p.ready.Store(true)
}

// processEvent dispatches an event to the correct Prometheus metric.
func (p *Prometheus) processEvent(e *event.Event) {
	p.eventsProcessed.WithLabelValues(e.Type.String()).Inc()

	switch e.Type {
	case event.TypeTCP:
		latency := e.NumericVal("latency_sec")
		p.tcpLatency.WithLabelValues(e.Namespace, e.Pod, e.Node).Observe(latency)

	case event.TypeDNS:
		domain := e.Label("domain")
		p.dnsQueries.WithLabelValues(e.Namespace, e.Pod, domain, e.Node).Inc()
		if latency := e.NumericVal("latency_sec"); latency > 0 {
			p.dnsLatency.WithLabelValues(e.Namespace, e.Pod, e.Node).Observe(latency)
		}

	case event.TypeRetransmit:
		p.retransmits.WithLabelValues(e.Namespace, e.Pod, e.Node).Inc()

	case event.TypeRST:
		p.tcpResets.WithLabelValues(e.Namespace, e.Pod, e.Node).Inc()

	case event.TypeOOM:
		p.oomKills.WithLabelValues(e.Namespace, e.Pod, e.Node).Inc()

	case event.TypeExec:
		p.processExecs.WithLabelValues(e.Namespace, e.Pod, e.Node).Inc()

	case event.TypeFileIO:
		op := e.Label("op")
		latency := e.NumericVal("latency_sec")
		p.fileIOLatency.WithLabelValues(e.Namespace, e.Pod, op, e.Node).Observe(latency)
		p.fileIOOps.WithLabelValues(e.Namespace, e.Pod, op, e.Node).Inc()

	case event.TypeDrop:
		reason := e.Label("reason")
		p.packetDrops.WithLabelValues(reason, e.Node).Inc()
	}
}

// collectBusStats periodically updates event bus self-observability metrics.
func (p *Prometheus) collectBusStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := p.bus.Stats()
			for name, depth := range stats.QueueDepth {
				p.busQueueDepth.WithLabelValues(name).Set(float64(depth))
			}
			for name, drops := range stats.DroppedBySubscriber {
				p.eventsDropped.WithLabelValues(name).Add(float64(drops))
			}
		}
	}
}

// FormatIPv4 converts a uint32 IPv4 address to dotted-decimal string.
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
