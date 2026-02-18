// Package probe defines the core Probe interface that all eBPF probes must implement.
// This is the extension point for the KubePulse agent — adding a new probe means
// creating a new package that satisfies this interface.
package probe

import "context"

// Probe defines the lifecycle contract for a pluggable eBPF probe.
//
// Each probe implementation owns its BPF program loading, hook attachment,
// ring buffer consumption, and resource cleanup. The Agent orchestrator
// manages the lifecycle by calling these methods in order:
//
//	Init() → Run(ctx) → Close()
type Probe interface {
	// Name returns a unique, human-readable identifier for this probe.
	// Used in logs, metrics labels, and error messages.
	// Examples: "tcp", "dns", "oom", "fileio"
	Name() string

	// Init loads the BPF program into the kernel, attaches hooks,
	// and creates ring buffer readers. Called once before Run.
	// Must be idempotent — calling Init after Close should work.
	Init() error

	// Run starts consuming events from the ring buffer.
	// It blocks until ctx is cancelled. Implementations should
	// handle ring buffer reads in a loop and dispatch events to
	// their configured handler callback.
	Run(ctx context.Context) error

	// Close releases all kernel resources: detaches hooks, closes
	// ring buffers, and unloads BPF objects. Called during shutdown.
	// Must be safe to call even if Init was never called or failed.
	Close() error
}
