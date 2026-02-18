// Package export provides the exporter interface and implementations.
// Exporters subscribe to the EventBus and convert events to external formats.
package export

import "context"

// Exporter defines the interface for event export backends.
// Each exporter subscribes to the EventBus and processes events
// in its own format (Prometheus, OTLP, etc.).
type Exporter interface {
	// Name returns a unique identifier for this exporter.
	Name() string

	// Start begins consuming events and exporting metrics/traces.
	// Blocks until ctx is cancelled.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the exporter.
	Stop(ctx context.Context) error
}
