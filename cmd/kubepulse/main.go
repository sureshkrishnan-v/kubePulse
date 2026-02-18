// KubePulse - eBPF-powered Kubernetes-aware observability agent.
//
// Probes: TCP latency, DNS queries, TCP retransmissions, TCP resets,
// OOM kills, process execs, file I/O latency, packet drops.
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
	version            = "2.0.0"
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
		zap.Int("probes", 8))

	metricsAddr := os.Getenv("KUBEPULSE_METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = defaultMetricsAddr
	}

	nodeName := os.Getenv("KUBEPULSE_NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize Prometheus metrics
	m := kubemetrics.New()

	// Initialize metadata cache
	metaCache := metadata.NewCache(metadata.DefaultCacheConfig())

	// Try to start Kubernetes watcher (optional)
	k8sEnabled := false
	k8sWatcher, err := metadata.NewK8sWatcher(metaCache, logger)
	if err != nil {
		logger.Warn("Kubernetes watcher not available", zap.Error(err))
	} else {
		k8sEnabled = true
		go func() {
			if err := k8sWatcher.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Kubernetes watcher error", zap.Error(err))
			}
		}()
	}

	// Load all BPF programs
	logger.Info("Loading eBPF programs...")
	lp, err := loader.Load()
	if err != nil {
		logger.Fatal("Failed to load eBPF programs", zap.Error(err))
	}
	defer lp.Close()
	logger.Info("All eBPF programs loaded",
		zap.Bool("k8s", k8sEnabled),
		zap.Strings("probes", []string{
			"tcp_connect", "tcp_close", "udp_sendmsg",
			"tcp_retransmit_skb", "tcp_send_reset",
			"oom/mark_victim", "sched_process_exec",
			"vfs_read", "vfs_write", "kfree_skb",
		}))

	// Helper: resolve PID to pod metadata
	resolvePod := func(pid uint32) (string, string) {
		if meta, found := metaCache.Lookup(pid); found {
			return meta.Namespace, meta.PodName
		}
		return "", ""
	}

	// ==================== Event Handlers ====================

	// --- TCP Latency ---
	handleTCP := func(event probes.TCPEvent) {
		latencySec := float64(event.LatencyNs) / 1e9
		ns, pod := resolvePod(event.PID)
		logger.Info("tcp",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("src", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.SAddr), event.SPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.DAddr), event.DPort)),
			zap.String("latency", formatDuration(event.LatencyNs)),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveTCPLatency(ns, pod, nodeName, latencySec)
	}

	// --- DNS ---
	handleDNS := func(event probes.DNSEvent) {
		domain := kubemetrics.TruncateDomain(event.QNameString())
		ns, pod := resolvePod(event.PID)
		logger.Info("dns",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("query", event.QNameString()),
			zap.String("domain", domain),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveDNSQuery(ns, pod, domain, nodeName)
	}

	// --- TCP Retransmit ---
	handleRetransmit := func(event probes.RetransmitEvent) {
		ns, pod := resolvePod(event.PID)
		logger.Warn("tcp_retransmit",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("src", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.SAddr), event.SPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.DAddr), event.DPort)),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveRetransmit(ns, pod, nodeName)
	}

	// --- TCP RST ---
	handleRST := func(event probes.RSTEvent) {
		ns, pod := resolvePod(event.PID)
		logger.Warn("tcp_rst",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("src", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.SAddr), event.SPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", probes.FormatIPv4(event.DAddr), event.DPort)),
			zap.Uint32("state", event.State),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveReset(ns, pod, nodeName)
	}

	// --- OOM Kill ---
	handleOOM := func(event probes.OOMEvent) {
		ns, pod := resolvePod(event.PID)
		logger.Error("oom_kill",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.Uint64("total_vm_kb", event.TotalVMKB()),
			zap.Uint64("anon_rss_pages", event.AnonRSS),
			zap.Int16("oom_score_adj", event.OOMScoreAdj),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveOOMKill(ns, pod, nodeName)
	}

	// --- Process Exec ---
	handleExec := func(event probes.ExecEvent) {
		ns, pod := resolvePod(event.PID)
		logger.Info("exec",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("filename", event.FilenameString()),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveExec(ns, pod, nodeName)
	}

	// --- File I/O ---
	handleFileIO := func(event probes.FileIOEvent) {
		latencySec := float64(event.LatencyNs) / 1e9
		ns, pod := resolvePod(event.PID)
		op := event.OpString()
		logger.Info("fileio",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("op", op),
			zap.Uint64("bytes", event.Bytes),
			zap.String("latency", formatDuration(event.LatencyNs)),
			zap.String("ns", ns), zap.String("pod", pod))
		m.ObserveFileIO(ns, pod, op, nodeName, latencySec)
	}

	// --- Packet Drop ---
	handleDrop := func(event probes.DropEvent) {
		reason := event.DropReasonString()
		logger.Warn("packet_drop",
			zap.Uint32("pid", event.PID),
			zap.String("comm", event.CommString()),
			zap.String("reason", reason),
			zap.Uint16("protocol", event.Protocol))
		m.ObservePacketDrop(reason, nodeName)
	}

	// ==================== Start Probes ====================

	type probeRunner struct {
		name string
		run  func()
	}

	runners := []probeRunner{
		{"tcp", func() {
			p := probes.NewTCPProbe(lp.TCPReader, logger, handleTCP)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("TCP probe error", zap.Error(err))
				cancel()
			}
		}},
		{"dns", func() {
			p := probes.NewDNSProbe(lp.DNSReader, logger, handleDNS)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("DNS probe error", zap.Error(err))
				cancel()
			}
		}},
		{"retransmit", func() {
			p := probes.NewRetransmitProbe(lp.RetransmitReader, logger, handleRetransmit)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Retransmit probe error", zap.Error(err))
				cancel()
			}
		}},
		{"rst", func() {
			p := probes.NewRSTProbe(lp.RSTReader, logger, handleRST)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("RST probe error", zap.Error(err))
				cancel()
			}
		}},
		{"oom", func() {
			p := probes.NewOOMProbe(lp.OOMReader, logger, handleOOM)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("OOM probe error", zap.Error(err))
				cancel()
			}
		}},
		{"exec", func() {
			p := probes.NewExecProbe(lp.ExecReader, logger, handleExec)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Exec probe error", zap.Error(err))
				cancel()
			}
		}},
		{"fileio", func() {
			p := probes.NewFileIOProbe(lp.FileIOReader, logger, handleFileIO)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("FileIO probe error", zap.Error(err))
				cancel()
			}
		}},
		{"drop", func() {
			p := probes.NewDropProbe(lp.DropReader, logger, handleDrop)
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Drop probe error", zap.Error(err))
				cancel()
			}
		}},
	}

	for _, r := range runners {
		go r.run()
	}

	// Start metrics exporter
	exp := exporter.New(metricsAddr, logger)
	exp.SetReady()
	go func() {
		if err := exp.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("Metrics exporter error", zap.Error(err))
			cancel()
		}
	}()

	logger.Info("KubePulse is running",
		zap.String("metrics", metricsAddr+"/metrics"),
		zap.String("node", nodeName),
		zap.Bool("k8s", k8sEnabled),
		zap.Int("active_probes", len(runners)))

	<-ctx.Done()
	logger.Info("Shutdown signal received, cleaning up...")
	time.Sleep(100 * time.Millisecond)

	pidEntries, containerEntries := metaCache.Stats()
	logger.Info("KubePulse stopped",
		zap.Int("cached_pids", pidEntries),
		zap.Int("cached_containers", containerEntries))
}

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
