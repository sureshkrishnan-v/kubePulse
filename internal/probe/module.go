// Package probe defines the Module interface that all KubePulse eBPF modules implement.
// This is the core extension point — each module owns its BPF program lifecycle
// and publishes events to the EventBus via Dependencies.
package probe

import (
	"context"

	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/config"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
	"github.com/sureshkrishnan-v/kubePulse/internal/metadata"
)

// Module defines the lifecycle contract for a pluggable eBPF module.
//
// Each module is responsible for:
//   - Loading its BPF program into the kernel
//   - Attaching hooks (kprobes, tracepoints)
//   - Consuming ring buffer events
//   - Enriching events with metadata
//   - Publishing to EventBus
//
// Lifecycle: Init(ctx, deps) → Start(ctx) → Stop(ctx)
type Module interface {
	// Name returns a unique identifier for this module.
	// Must match the config key (e.g., "tcp", "dns", "oom").
	Name() string

	// Init loads BPF programs, attaches hooks, and prepares ring buffers.
	// Dependencies are injected here — the module stores them for later use.
	Init(ctx context.Context, deps Dependencies) error

	// Start begins the event consumption loop.
	// Must block until ctx is cancelled or an unrecoverable error occurs.
	// Events are published to deps.EventBus (received in Init).
	Start(ctx context.Context) error

	// Stop gracefully shuts down the module.
	// The ctx has a deadline — the module must finish within it.
	// Releases all kernel resources (BPF objects, links, ring buffers).
	Stop(ctx context.Context) error
}

// Dependencies provides all shared resources a module needs.
// Injected during Init() — no global state, no constructor injection.
type Dependencies struct {
	// Logger for structured logging
	Logger *zap.Logger

	// Config for this specific module
	Config *config.ModuleConfig

	// EventBus for publishing events
	EventBus *event.Bus

	// Metadata cache for PID → pod/namespace resolution
	Metadata *metadata.Cache

	// NodeName for metric labels
	NodeName string
}
