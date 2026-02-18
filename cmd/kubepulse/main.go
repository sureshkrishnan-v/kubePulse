// KubePulse — eBPF-powered, modular Kubernetes observability agent.
//
// Architecture: pluggable Module system with EventBus (Observer pattern).
// Each module publishes events to the bus; exporters subscribe and consume.
//
// Design patterns used:
//   - Factory: New() constructors for all modules and exporters
//   - Registry: Runtime.RegisterModule / RegisterExporter
//   - Observer: EventBus pub/sub decouples producers from consumers
//   - Strategy: each Module encapsulates a specific BPF monitoring strategy
//   - DI: Dependencies struct injected into modules at Init time
//   - Facade: Runtime.Run() orchestrates all subsystems
package main

import (
	"context"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sureshkrishnan-v/kubePulse/internal/agent"
	"github.com/sureshkrishnan-v/kubePulse/internal/config"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/export"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/dns"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/drop"
	execprobe "github.com/sureshkrishnan-v/kubePulse/internal/probes/exec"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/fileio"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/oom"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/retransmit"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/rst"
	"github.com/sureshkrishnan-v/kubePulse/internal/probes/tcp"
)

func main() {
	// Logger
	logCfg := zap.NewProductionConfig()
	logCfg.EncoderConfig.TimeKey = "ts"
	logCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ := logCfg.Build()
	defer logger.Sync()

	logger.Info("KubePulse starting", zap.String("version", constants.Version))

	// Config (YAML + env overrides)
	cfg, err := config.Load(constants.DefaultConfigPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	// Runtime (Facade pattern)
	rt := agent.NewRuntime(cfg, logger)

	// ─── Register modules (Factory + Registry pattern) ─────────
	// Each module uses New() constructor — no raw struct literals.
	// To add a new module:
	//   1. Create internal/probes/yourmodule/ package
	//   2. Implement probe.Module interface
	//   3. Add one line here: rt.RegisterModule(yourmodule.New())
	rt.RegisterModule(tcp.New())
	rt.RegisterModule(dns.New())
	rt.RegisterModule(retransmit.New())
	rt.RegisterModule(rst.New())
	rt.RegisterModule(oom.New())
	rt.RegisterModule(execprobe.New())
	rt.RegisterModule(fileio.New())
	rt.RegisterModule(drop.New())

	// ─── Register exporters (Observer pattern) ─────────────────
	// Prometheus exporter subscribes to EventBus automatically.
	// Future: add OTLP, Kafka, etc.
	rt.RegisterExporter(export.NewPrometheus(
		cfg.Exporters.Prometheus.Addr, rt.EventBus(), logger,
	))

	// ─── Run (Facade pattern) ──────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := rt.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Fatal("Runtime error", zap.Error(err))
	}
}
