// Package agent provides the KubePulse runtime orchestrator.
// It manages the full lifecycle of modules, exporters, event bus,
// and metadata enrichment.
package agent

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/config"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
	"github.com/sureshkrishnan-v/kubePulse/internal/export"
	"github.com/sureshkrishnan-v/kubePulse/internal/metadata"
	"github.com/sureshkrishnan-v/kubePulse/internal/probe"
)

// Runtime is the central orchestrator for KubePulse.
// It manages the lifecycle of all modules, exporters, event bus,
// metadata cache, and graceful shutdown.
//
// Design pattern: Facade — provides a single entry point (Run) that
// orchestrates all subsystems. Also implements the Registry pattern
// for module/exporter registration.
type Runtime struct {
	cfg       *config.Config
	logger    *zap.Logger
	modules   []probe.Module
	exporters []export.Exporter
	bus       *event.Bus
	metaCache *metadata.Cache
}

// NewRuntime creates a new Runtime with the given configuration.
// The EventBus is created eagerly so exporters can subscribe before Run().
func NewRuntime(cfg *config.Config, logger *zap.Logger) *Runtime {
	return &Runtime{
		cfg:    cfg,
		logger: logger,
		bus:    event.NewBus(cfg.Performance.EventBusBuffer, logger),
	}
}

// RegisterModule adds a module to the runtime (Registry pattern).
// The module will only be initialized if enabled in config.
// Must be called before Run.
func (rt *Runtime) RegisterModule(m probe.Module) {
	rt.modules = append(rt.modules, m)
}

// RegisterExporter adds an exporter to the runtime (Registry pattern).
// Must be called before Run.
func (rt *Runtime) RegisterExporter(e export.Exporter) {
	rt.exporters = append(rt.exporters, e)
}

// EventBus returns the event bus for exporter subscription.
func (rt *Runtime) EventBus() *event.Bus {
	return rt.bus
}

// MetaCache returns the metadata cache for PID resolution.
func (rt *Runtime) MetaCache() *metadata.Cache {
	return rt.metaCache
}

// Run starts the full runtime lifecycle:
//  1. Pre-flight checks (root, rlimit)
//  2. Init metadata cache + K8s watcher
//  3. Init all enabled modules (skip disabled)
//  4. Start exporters
//  5. Start all initialized modules
//  6. Wait for shutdown signal
//  7. Stop modules → close bus → stop exporters
func (rt *Runtime) Run(ctx context.Context) error {
	// Pre-flight checks
	if os.Geteuid() != 0 {
		return fmt.Errorf("KubePulse requires root privileges. Run with: sudo ./bin/kubepulse")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		rt.logger.Warn("Failed to remove memlock rlimit", zap.Error(err))
	}

	rt.logger.Info("KubePulse runtime starting",
		zap.Int("modules_registered", len(rt.modules)),
		zap.Int("exporters_registered", len(rt.exporters)),
		zap.String("node", rt.cfg.Agent.NodeName))

	// Initialize metadata cache
	rt.metaCache = metadata.NewCache(metadata.DefaultCacheConfig())

	// Start Kubernetes watcher (optional — degrades gracefully)
	k8sWatcher, err := metadata.NewK8sWatcher(rt.metaCache, rt.logger)
	if err != nil {
		rt.logger.Warn("Kubernetes watcher unavailable — pod labels will be empty", zap.Error(err))
	} else {
		go func() {
			if err := k8sWatcher.Run(ctx); err != nil && ctx.Err() == nil {
				rt.logger.Error("Kubernetes watcher error", zap.Error(err))
			}
		}()
	}

	// Initialize enabled modules
	var initialized []probe.Module
	for _, m := range rt.modules {
		if !rt.cfg.ModuleEnabled(m.Name()) {
			rt.logger.Info("Module disabled by config — skipping",
				zap.String("module", m.Name()))
			continue
		}

		deps := probe.NewDependencies(
			rt.logger.Named(m.Name()),
			rt.cfg.ModuleConf(m.Name()),
			rt.bus,
			rt.metaCache,
			rt.cfg.Agent.NodeName,
		)

		rt.logger.Info("Initializing module", zap.String("module", m.Name()))
		if err := m.Init(ctx, deps); err != nil {
			rt.logger.Error("Module init failed — skipping",
				zap.String("module", m.Name()), zap.Error(err))
			continue
		}
		initialized = append(initialized, m)
		rt.logger.Info("Module initialized", zap.String("module", m.Name()))
	}

	if len(initialized) == 0 {
		return fmt.Errorf("no modules initialized successfully")
	}

	// Start exporters
	var wg sync.WaitGroup
	for _, e := range rt.exporters {
		wg.Add(1)
		go func(e export.Exporter) {
			defer wg.Done()
			rt.logger.Info("Starting exporter", zap.String("exporter", e.Name()))
			if err := e.Start(ctx); err != nil && ctx.Err() == nil {
				rt.logger.Error("Exporter error",
					zap.String("exporter", e.Name()), zap.Error(err))
			}
		}(e)
	}

	// Start all initialized modules
	for _, m := range initialized {
		wg.Add(1)
		go func(m probe.Module) {
			defer wg.Done()
			rt.logger.Info("Starting module", zap.String("module", m.Name()))
			if err := m.Start(ctx); err != nil && ctx.Err() == nil {
				rt.logger.Error("Module error",
					zap.String("module", m.Name()), zap.Error(err))
			}
		}(m)
	}

	// Log active state
	names := make([]string, len(initialized))
	for i, m := range initialized {
		names[i] = m.Name()
	}
	exporterNames := make([]string, len(rt.exporters))
	for i, e := range rt.exporters {
		exporterNames[i] = e.Name()
	}
	rt.logger.Info("KubePulse running",
		zap.Strings("modules", names),
		zap.Strings("exporters", exporterNames))

	// Wait for shutdown signal
	<-ctx.Done()
	rt.logger.Info("Shutdown signal received")

	// Stop modules (with timeout)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), constants.ShutdownTimeout)
	defer stopCancel()

	for _, m := range initialized {
		rt.logger.Debug("Stopping module", zap.String("module", m.Name()))
		if err := m.Stop(stopCtx); err != nil {
			rt.logger.Warn("Error stopping module",
				zap.String("module", m.Name()), zap.Error(err))
		}
	}

	// Close event bus (triggers exporter channel close)
	rt.bus.Close()

	// Stop exporters
	for _, e := range rt.exporters {
		rt.logger.Debug("Stopping exporter", zap.String("exporter", e.Name()))
		if err := e.Stop(stopCtx); err != nil {
			rt.logger.Warn("Error stopping exporter",
				zap.String("exporter", e.Name()), zap.Error(err))
		}
	}

	wg.Wait()

	rt.logger.Info("KubePulse stopped",
		zap.Int("modules_stopped", len(initialized)),
		zap.Uint64("events_published", rt.bus.Published()),
		zap.Uint64("events_dropped", rt.bus.Dropped()))

	return nil
}
