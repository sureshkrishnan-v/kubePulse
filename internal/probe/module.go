// Package probe defines the Module interface — the contract for all
// pluggable eBPF modules in KubePulse.
//
// Design patterns:
//   - Strategy: each Module implementation encapsulates a specific BPF strategy
//   - Dependency Injection: Dependencies struct injected during Init()
//   - Template Method: Name/Init/Start/Stop lifecycle enforced by interface
package probe

import (
	"context"

	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/config"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
	"github.com/sureshkrishnan-v/kubePulse/internal/metadata"
)

// Module is the lifecycle interface for all eBPF modules.
//
// Lifecycle:
//  1. Name() — returns unique module identifier
//  2. Init(ctx, deps) — load BPF objects, attach hooks, create readers
//  3. Start(ctx) — consume ring buffer events and publish to EventBus
//  4. Stop(ctx) — release kernel resources within deadline
type Module interface {
	// Name returns a unique, human-readable identifier.
	Name() string

	// Init loads BPF programs, attaches hooks, creates ring buffer readers.
	// Dependencies are injected here (DI pattern).
	Init(ctx context.Context, deps Dependencies) error

	// Start begins consuming events from the ring buffer.
	// Blocks until ctx is cancelled. Publishes to EventBus.
	Start(ctx context.Context) error

	// Stop releases all kernel resources within the context deadline.
	Stop(ctx context.Context) error
}

// Dependencies holds all shared resources injected into modules.
// This implements the Dependency Injection (DI) pattern — modules
// declare what they need, the runtime provides it.
type Dependencies struct {
	Logger   *zap.Logger
	Config   *config.ModuleConfig
	EventBus *event.Bus
	Metadata *metadata.Cache
	NodeName string
}

// NewDependencies creates a Dependencies struct with all required fields.
// This is the canonical constructor — never use a raw struct literal.
func NewDependencies(
	logger *zap.Logger,
	cfg *config.ModuleConfig,
	bus *event.Bus,
	meta *metadata.Cache,
	nodeName string,
) Dependencies {
	return Dependencies{
		Logger:   logger,
		Config:   cfg,
		EventBus: bus,
		Metadata: meta,
		NodeName: nodeName,
	}
}
