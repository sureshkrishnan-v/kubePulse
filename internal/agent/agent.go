// Package agent provides the KubePulse agent orchestrator.
// It manages probe lifecycle, metrics export, metadata enrichment,
// and graceful shutdown.
package agent

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/exporter"
	"github.com/sureshkrishnan-v/kubePulse/internal/metadata"
	"github.com/sureshkrishnan-v/kubePulse/internal/probe"
)

// Agent is the central orchestrator for KubePulse.
// It manages the lifecycle of all registered probes, the metrics exporter,
// and the Kubernetes metadata enricher.
type Agent struct {
	cfg    *Config
	logger *zap.Logger
	probes []probe.Probe

	MetaCache *metadata.Cache
	Exporter  *exporter.Server

	mu sync.Mutex
}

// New creates a new Agent with the given configuration.
func New(cfg *Config, logger *zap.Logger) *Agent {
	return &Agent{
		cfg:    cfg,
		logger: logger,
	}
}

// Register adds a probe to the agent. Must be called before Run.
// Probes are initialized and started in registration order.
func (a *Agent) Register(p probe.Probe) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.probes = append(a.probes, p)
}

// Run starts the agent: initializes all probes, starts the metrics exporter,
// and begins consuming events. Blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	// Pre-flight checks
	if os.Geteuid() != 0 {
		return fmt.Errorf("KubePulse requires root privileges. Run with: sudo ./bin/kubepulse")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		a.logger.Warn("Failed to remove memlock rlimit (may not be needed on kernel >= 5.11)", zap.Error(err))
	}

	a.logger.Info("Initializing agent",
		zap.Int("probes", len(a.probes)),
		zap.String("metrics_addr", a.cfg.MetricsAddr),
		zap.String("node", a.cfg.NodeName))

	// Initialize metadata cache
	a.MetaCache = metadata.NewCache(metadata.DefaultCacheConfig())

	// Start Kubernetes watcher (optional — degrades gracefully)
	k8sWatcher, err := metadata.NewK8sWatcher(a.MetaCache, a.logger)
	if err != nil {
		a.logger.Warn("Kubernetes watcher unavailable — pod/namespace labels will be empty", zap.Error(err))
	} else {
		go func() {
			if err := k8sWatcher.Run(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("Kubernetes watcher error", zap.Error(err))
			}
		}()
	}

	// Initialize all probes (load BPF programs, attach hooks)
	var initialized []probe.Probe
	for _, p := range a.probes {
		a.logger.Info("Initializing probe", zap.String("name", p.Name()))
		if err := p.Init(); err != nil {
			a.logger.Error("Failed to initialize probe — skipping",
				zap.String("name", p.Name()), zap.Error(err))
			continue
		}
		initialized = append(initialized, p)
		a.logger.Info("Probe initialized", zap.String("name", p.Name()))
	}

	if len(initialized) == 0 {
		return fmt.Errorf("no probes initialized successfully")
	}

	// Start metrics exporter
	a.Exporter = exporter.New(a.cfg.MetricsAddr, a.logger)
	a.Exporter.SetReady()
	go func() {
		if err := a.Exporter.Run(ctx); err != nil && ctx.Err() == nil {
			a.logger.Error("Metrics exporter error", zap.Error(err))
		}
	}()

	// Start all probe consumers
	var wg sync.WaitGroup
	for _, p := range initialized {
		wg.Add(1)
		go func(p probe.Probe) {
			defer wg.Done()
			a.logger.Info("Starting probe consumer", zap.String("name", p.Name()))
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("Probe consumer error",
					zap.String("name", p.Name()), zap.Error(err))
			}
		}(p)
	}

	// Log active probes
	names := make([]string, len(initialized))
	for i, p := range initialized {
		names[i] = p.Name()
	}
	a.logger.Info("Agent running",
		zap.Strings("active_probes", names),
		zap.String("metrics", a.cfg.MetricsAddr+"/metrics"))

	// Wait for shutdown signal
	<-ctx.Done()
	a.logger.Info("Shutdown signal received")

	// Close all probes
	for _, p := range initialized {
		a.logger.Debug("Closing probe", zap.String("name", p.Name()))
		if err := p.Close(); err != nil {
			a.logger.Warn("Error closing probe",
				zap.String("name", p.Name()), zap.Error(err))
		}
	}

	wg.Wait()
	a.logger.Info("Agent stopped", zap.Int("probes_closed", len(initialized)))
	return nil
}

// ResolvePod looks up Kubernetes pod metadata for a given PID.
// Returns empty strings if not found or metadata cache is not initialized.
func (a *Agent) ResolvePod(pid uint32) (namespace, pod string) {
	if a.MetaCache == nil {
		return "", ""
	}
	if meta, found := a.MetaCache.Lookup(pid); found {
		return meta.Namespace, meta.PodName
	}
	return "", ""
}
