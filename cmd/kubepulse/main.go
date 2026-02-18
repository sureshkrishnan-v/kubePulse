// KubePulse — eBPF-powered Kubernetes-aware observability agent.
//
// Architecture: pluggable probe system. Each probe is a self-contained package
// implementing probe.Probe. To add a new probe: create a package, register here.
package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sureshkrishnan-v/kubePulse/internal/agent"
	kubemetrics "github.com/sureshkrishnan-v/kubePulse/internal/metrics"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/dns"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/drop"
	execprobe "github.com/sureshkrishnan-v/kubePulse/internal/probes/exec"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/fileio"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/oom"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/retransmit"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/rst"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/tcp"
)

const version = "3.0.0"

func main() {
	// Logger
	logCfg := zap.NewProductionConfig()
	logCfg.EncoderConfig.TimeKey = "ts"
	logCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ := logCfg.Build()
	defer logger.Sync()

	logger.Info("KubePulse starting", zap.String("version", version))

	// Config
	cfg := agent.LoadConfig()

	// Metrics
	m := kubemetrics.New()

	// Agent
	a := agent.New(cfg, logger)

	// ─── Register probes ───────────────────────────────────────
	// To add a new probe:
	//   1. Create internal/probes/yourprobe/ package
	//   2. Add one line here: a.Register(yourprobe.New(logger, handler))
	//   That's it.

	a.Register(tcp.New(logger, func(e tcp.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveTCPLatency(ns, pod, cfg.NodeName, float64(e.LatencyNs)/1e9)
		logger.Info("tcp",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("src", fmt.Sprintf("%s:%d", tcp.FormatIPv4(e.SAddr), e.SPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", tcp.FormatIPv4(e.DAddr), e.DPort)),
			zap.String("latency", fmtDuration(e.LatencyNs)),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(dns.New(logger, func(e dns.Event) {
		ns, pod := a.ResolvePod(e.PID)
		domain := dns.TruncateDomain(e.QNameString())
		m.ObserveDNSQuery(ns, pod, domain, cfg.NodeName)
		logger.Info("dns",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("query", e.QNameString()), zap.String("domain", domain),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(retransmit.New(logger, func(e retransmit.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveRetransmit(ns, pod, cfg.NodeName)
		logger.Warn("tcp_retransmit",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(rst.New(logger, func(e rst.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveReset(ns, pod, cfg.NodeName)
		logger.Warn("tcp_rst",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(oom.New(logger, func(e oom.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveOOMKill(ns, pod, cfg.NodeName)
		logger.Error("oom_kill",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.Uint64("total_vm_kb", e.TotalVMKB()),
			zap.Int16("oom_score_adj", e.OOMScoreAdj),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(execprobe.New(logger, func(e execprobe.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveExec(ns, pod, cfg.NodeName)
		logger.Info("exec",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("filename", e.FilenameString()),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(fileio.New(logger, func(e fileio.Event) {
		ns, pod := a.ResolvePod(e.PID)
		m.ObserveFileIO(ns, pod, e.OpString(), cfg.NodeName, float64(e.LatencyNs)/1e9)
		logger.Info("fileio",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("op", e.OpString()), zap.Uint64("bytes", e.Bytes),
			zap.String("latency", fmtDuration(e.LatencyNs)),
			zap.String("ns", ns), zap.String("pod", pod))
	}))

	a.Register(drop.New(logger, func(e drop.Event) {
		m.ObservePacketDrop(e.DropReasonString(), cfg.NodeName)
		logger.Warn("packet_drop",
			zap.Uint32("pid", e.PID), zap.String("comm", e.CommString()),
			zap.String("reason", e.DropReasonString()))
	}))

	// ─── Run agent ─────────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Fatal("Agent error", zap.Error(err))
	}
}

func fmtDuration(ns uint64) string {
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
