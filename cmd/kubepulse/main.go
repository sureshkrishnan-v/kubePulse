// KubePulse - eBPF-powered Kubernetes-aware TCP latency and DNS monitoring agent.
//
// Phase 4: Full-featured agent with TCP/DNS tracing, Prometheus metrics,
// and Kubernetes metadata enrichment (PID → pod/namespace labels).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sureshkrishnan-v/kubePulse/internal/exporter"
	"github.com/sureshkrishnan-v/kubePulse/internal/loader"
	"github.com/sureshkrishnan-v/kubePulse/internal/metadata"
	kubemetrics "github.com/sureshkrishnan-v/kubePulse/internal/metrics"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	defaultMetricsAddr = ":9090"
	version            = "0.4.0"
)

func main() {
	// Initialize structured logger
	logConfig := zap.NewProductionConfig()
	logConfig.EncoderConfig.TimeKey = "ts"
	logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, err := logConfig.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("KubePulse starting",
		zap.String("version", version),
		zap.String("phase", "4-kubernetes-metadata"))

	// Determine metrics listen address
	metricsAddr := os.Getenv("KUBEPULSE_METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = defaultMetricsAddr
	}

	// Context with signal-based cancellation for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize Prometheus metrics
	m := kubemetrics.New()

	// Initialize metadata cache
	metaCache := metadata.NewCache(metadata.DefaultCacheConfig())

	// Node name for labels (from env, set by Kubernetes downward API)
	nodeName := os.Getenv("KUBEPULSE_NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	// Try to start Kubernetes watcher (optional - may not be in a k8s cluster)
	k8sEnabled := false
	k8sWatcher, err := metadata.NewK8sWatcher(metaCache, logger)
	if err != nil {
		logger.Warn("Kubernetes watcher not available (running outside cluster?)",
			zap.Error(err))
	} else {
		k8sEnabled = true
		go func() {
			if err := k8sWatcher.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Kubernetes watcher exited with error", zap.Error(err))
			}
		}()
	}

	// Load BPF programs and attach kprobes
	logger.Info("Loading eBPF programs and attaching kprobes...")
	lp, err := loader.Load()
	if err != nil {
		logger.Fatal("Failed to load eBPF programs", zap.Error(err))
	}
	defer lp.Close()
	logger.Info("eBPF programs loaded and kprobes attached successfully",
		zap.Strings("probes", []string{"tcp_connect", "tcp_close", "udp_sendmsg"}),
		zap.Bool("k8s_enabled", k8sEnabled))

	// TCP event handler: enriches with metadata + records Prometheus metrics
	handleTCPEvent := func(event probes.TCPEvent) {
		latencyMs := float64(event.LatencyNs) / 1e6
		latencySec := float64(event.LatencyNs) / 1e9

		// Resolve PID → pod/namespace metadata
		podNs := ""
		podName := ""
		if meta, found := metaCache.Lookup(event.PID); found {
			podNs = meta.Namespace
			podName = meta.PodName
		}

		logger.Info("tcp_event",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("src", fmt.Sprintf("%s:%d",
				probes.FormatIPv4(event.SAddr), event.SPort)),
			zap.String("dst", fmt.Sprintf("%s:%d",
				probes.FormatIPv4(event.DAddr), event.DPort)),
			zap.Float64("latency_ms", latencyMs),
			zap.String("latency_human", formatDuration(event.LatencyNs)),
			zap.String("namespace", podNs),
			zap.String("pod", podName),
		)

		m.ObserveTCPLatency(podNs, podName, nodeName, latencySec)
	}

	// DNS event handler: enriches with metadata + records Prometheus metrics
	handleDNSEvent := func(event probes.DNSEvent) {
		qname := event.QNameString()
		domain := kubemetrics.TruncateDomain(qname)

		// Resolve PID → pod/namespace metadata
		podNs := ""
		podName := ""
		if meta, found := metaCache.Lookup(event.PID); found {
			podNs = meta.Namespace
			podName = meta.PodName
		}

		logger.Info("dns_event",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("query", qname),
			zap.String("domain", domain),
			zap.String("dns_server", fmt.Sprintf("%s:%d",
				probes.FormatIPv4(event.DAddr), event.DPort)),
			zap.String("namespace", podNs),
			zap.String("pod", podName),
		)

		m.ObserveDNSQuery(podNs, podName, domain, nodeName)
	}

	// Start TCP probe consumer
	tcpProbe := probes.NewTCPProbe(lp.TCPReader, logger, handleTCPEvent)
	go func() {
		if err := tcpProbe.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("TCP probe exited with error", zap.Error(err))
			cancel()
		}
	}()

	// Start DNS probe consumer
	dnsProbe := probes.NewDNSProbe(lp.DNSReader, logger, handleDNSEvent)
	go func() {
		if err := dnsProbe.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("DNS probe exited with error", zap.Error(err))
			cancel()
		}
	}()

	// Start metrics exporter HTTP server
	exp := exporter.New(metricsAddr, logger)
	exp.SetReady()
	go func() {
		if err := exp.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("Metrics exporter exited with error", zap.Error(err))
			cancel()
		}
	}()

	logger.Info("KubePulse is running",
		zap.String("metrics", metricsAddr+"/metrics"),
		zap.String("node", nodeName),
		zap.Bool("k8s_metadata", k8sEnabled))

	// Block until shutdown signal
	<-ctx.Done()
	logger.Info("Shutdown signal received, cleaning up...")

	// Give a brief moment for in-flight events
	time.Sleep(100 * time.Millisecond)

	pidEntries, containerEntries := metaCache.Stats()
	logger.Info("KubePulse stopped",
		zap.Uint64("tcp_events_dropped", tcpProbe.DroppedCount()),
		zap.Uint64("dns_events_dropped", dnsProbe.DroppedCount()),
		zap.Int("cached_pids", pidEntries),
		zap.Int("cached_containers", containerEntries))
}

// formatDuration converts nanoseconds to a human-readable duration string.
func formatDuration(ns uint64) string {
	d := time.Duration(ns) * time.Nanosecond
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.3fs", float64(d)/float64(time.Second))
	}
}
