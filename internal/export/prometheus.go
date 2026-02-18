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

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
)

// Prometheus is an Exporter that consumes events from the EventBus
// and updates Prometheus metrics. Implements the Exporter interface.
type Prometheus struct {
	addr   string
	logger *zap.Logger
	bus    *event.Bus
	events <-chan *event.Event
	server *http.Server
	ready  atomic.Bool

	// Network metrics
	tcpLatency  *prometheus.HistogramVec
	dnsQueries  *prometheus.CounterVec
	dnsLatency  *prometheus.HistogramVec
	retransmits *prometheus.CounterVec
	tcpResets   *prometheus.CounterVec
	packetDrops *prometheus.CounterVec

	// System metrics
	oomKills      *prometheus.CounterVec
	processExecs  *prometheus.CounterVec
	fileIOLatency *prometheus.HistogramVec
	fileIOOps     *prometheus.CounterVec

	// Self-observability metrics
	eventsProcessed *prometheus.CounterVec
	eventsDropped   *prometheus.CounterVec
	busQueueDepth   *prometheus.GaugeVec
	moduleErrors    *prometheus.CounterVec
}

// NewPrometheus creates a Prometheus exporter that subscribes to the EventBus.
// All metric names, buckets, and labels are sourced from the constants package.
func NewPrometheus(addr string, bus *event.Bus, logger *zap.Logger) *Prometheus {
	p := &Prometheus{
		addr:   addr,
		logger: logger,
		bus:    bus,

		// --- Network Metrics ---
		tcpLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    constants.MetricTCPLatency,
			Help:    "TCP connection latency.",
			Buckets: constants.NetworkLatencyBuckets,
		}, constants.LabelsNamespacePodNode),

		dnsQueries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricDNSQueries,
			Help: "Total DNS queries observed.",
		}, constants.LabelsNamespacePodDomainNode),

		dnsLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    constants.MetricDNSLatency,
			Help:    "DNS query latency.",
			Buckets: constants.NetworkLatencyBuckets,
		}, constants.LabelsNamespacePodNode),

		retransmits: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricTCPRetransmits,
			Help: "Total TCP retransmissions.",
		}, constants.LabelsNamespacePodNode),

		tcpResets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricTCPResets,
			Help: "Total TCP connection resets.",
		}, constants.LabelsNamespacePodNode),

		packetDrops: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricPacketDrops,
			Help: "Total packets dropped by kernel.",
		}, constants.LabelsReasonNode),

		// --- System Metrics ---
		oomKills: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricOOMKills,
			Help: "Total OOM kill events.",
		}, constants.LabelsNamespacePodNode),

		processExecs: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricProcessExecs,
			Help: "Total process executions.",
		}, constants.LabelsNamespacePodNode),

		fileIOLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    constants.MetricFileIOLatency,
			Help:    "File I/O latency.",
			Buckets: constants.IOLatencyBuckets,
		}, constants.LabelsNamespacePodOpNode),

		fileIOOps: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricFileIOOps,
			Help: "Total slow file I/O operations.",
		}, constants.LabelsNamespacePodOpNode),

		// --- Self-Observability ---
		eventsProcessed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricEventsProcessed,
			Help: "Total events processed by exporter.",
		}, constants.LabelsModule),

		eventsDropped: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricEventsDropped,
			Help: "Total events dropped due to backpressure.",
		}, constants.LabelsSubscriber),

		busQueueDepth: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: constants.MetricBusQueueDepth,
			Help: "Current event bus queue depth per subscriber.",
		}, constants.LabelsSubscriber),

		moduleErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: constants.MetricModuleErrors,
			Help: "Total errors by module.",
		}, constants.LabelsModule),
	}

	// Subscribe to event bus
	p.events = bus.Subscribe(constants.ExporterPrometheus)

	return p
}

func (p *Prometheus) Name() string { return constants.ExporterPrometheus }

func (p *Prometheus) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(constants.PathMetrics, promhttp.Handler())
	mux.HandleFunc(constants.PathHealthz, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc(constants.PathReadyz, func(w http.ResponseWriter, r *http.Request) {
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
		ReadTimeout:  constants.HTTPReadTimeout,
		WriteTimeout: constants.HTTPWriteTimeout,
		IdleTimeout:  constants.HTTPIdleTimeout,
	}

	go func() {
		p.logger.Info("Prometheus exporter listening",
			zap.String("addr", p.addr),
			zap.String("path", constants.PathMetrics))
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Error("Prometheus HTTP server error", zap.Error(err))
		}
	}()

	go p.collectBusStats(ctx)

	p.ready.Store(true)

	// Main event consumption loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-p.events:
			if !ok {
				return nil
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
// Uses constants for event label/numeric keys — Strategy pattern for dispatch.
func (p *Prometheus) processEvent(e *event.Event) {
	p.eventsProcessed.WithLabelValues(e.Type.String()).Inc()

	switch e.Type {
	case event.TypeTCP:
		p.tcpLatency.WithLabelValues(e.Namespace, e.Pod, e.Node).
			Observe(e.NumericVal(constants.KeyLatencySec))

	case event.TypeDNS:
		p.dnsQueries.WithLabelValues(e.Namespace, e.Pod, e.Label(constants.KeyDomain), e.Node).Inc()
		if latency := e.NumericVal(constants.KeyLatencySec); latency > 0 {
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
		op := e.Label(constants.KeyOp)
		p.fileIOLatency.WithLabelValues(e.Namespace, e.Pod, op, e.Node).
			Observe(e.NumericVal(constants.KeyLatencySec))
		p.fileIOOps.WithLabelValues(e.Namespace, e.Pod, op, e.Node).Inc()

	case event.TypeDrop:
		p.packetDrops.WithLabelValues(e.Label(constants.KeyReason), e.Node).Inc()
	}
}

// collectBusStats periodically updates event bus self-observability metrics.
func (p *Prometheus) collectBusStats(ctx context.Context) {
	ticker := time.NewTicker(constants.StatsCollectInterval)
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
