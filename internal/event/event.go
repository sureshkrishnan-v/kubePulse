// Package event provides the unified event type and event bus for KubePulse.
// All modules publish events to the bus; exporters subscribe and consume them.
package event

import (
	"sync"
	"time"
)

// EventType identifies the source module of an event.
type EventType uint8

const (
	TypeUnknown    EventType = iota
	TypeTCP                  // TCP connection latency
	TypeDNS                  // DNS query
	TypeRetransmit           // TCP retransmission
	TypeRST                  // TCP connection reset
	TypeOOM                  // OOM kill
	TypeExec                 // Process execution
	TypeFileIO               // File I/O latency
	TypeDrop                 // Packet drop
)

// String returns the human-readable name of the event type.
func (t EventType) String() string {
	switch t {
	case TypeTCP:
		return "tcp"
	case TypeDNS:
		return "dns"
	case TypeRetransmit:
		return "retransmit"
	case TypeRST:
		return "rst"
	case TypeOOM:
		return "oom"
	case TypeExec:
		return "exec"
	case TypeFileIO:
		return "fileio"
	case TypeDrop:
		return "drop"
	default:
		return "unknown"
	}
}

// Event is the unified envelope for all eBPF events flowing through KubePulse.
// Pool-allocated — call Release() when done to avoid GC pressure.
//
// Design: structured fields for common attributes + maps for type-specific data.
// This avoids massive union structs while keeping a single pipeline type.
type Event struct {
	Type      EventType
	Timestamp time.Time

	// Process identity
	PID  uint32
	UID  uint32
	Comm string

	// Kubernetes context (enriched by metadata cache)
	Node      string
	Namespace string
	Pod       string

	// Type-specific key-value fields (low cardinality strings)
	Labels map[string]string

	// Type-specific numeric values (latency, bytes, scores)
	Numeric map[string]float64
}

// pool is the sync.Pool for Event objects, reducing GC pressure on the hot path.
var pool = sync.Pool{
	New: func() any {
		return &Event{
			Labels:  make(map[string]string, 4),
			Numeric: make(map[string]float64, 4),
		}
	},
}

// Acquire retrieves a pre-allocated Event from the pool.
// The caller must call Release() when done processing the event.
func Acquire() *Event {
	e := pool.Get().(*Event)
	return e
}

// Release returns the Event to the pool after clearing all fields.
// The event must not be used after calling Release.
func (e *Event) Release() {
	// Clear fields but keep allocated maps
	e.Type = TypeUnknown
	e.Timestamp = time.Time{}
	e.PID = 0
	e.UID = 0
	e.Comm = ""
	e.Node = ""
	e.Namespace = ""
	e.Pod = ""
	for k := range e.Labels {
		delete(e.Labels, k)
	}
	for k := range e.Numeric {
		delete(e.Numeric, k)
	}
	pool.Put(e)
}

// SetLabel sets a type-specific string attribute.
func (e *Event) SetLabel(key, value string) {
	e.Labels[key] = value
}

// SetNumeric sets a type-specific numeric attribute.
func (e *Event) SetNumeric(key string, value float64) {
	e.Numeric[key] = value
}

// Label returns a label value, or empty string if not present.
func (e *Event) Label(key string) string {
	return e.Labels[key]
}

// NumericVal returns a numeric value, or 0 if not present.
func (e *Event) NumericVal(key string) float64 {
	return e.Numeric[key]
}
