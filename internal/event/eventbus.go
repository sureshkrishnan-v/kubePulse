package event

import (
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// Bus is a high-performance event distribution system.
//
// Modules publish events; exporters subscribe and consume them.
// Design constraints:
//   - Non-blocking publish (drops on overflow)
//   - Bounded per-subscriber buffers
//   - Drop metrics tracked per subscriber
//   - Thread-safe for concurrent publishers
type Bus struct {
	logger      *zap.Logger
	bufferSize  int
	subscribers map[string]chan *Event
	mu          sync.RWMutex
	closed      atomic.Bool

	// Metrics
	published atomic.Uint64
	dropped   map[string]*atomic.Uint64
	dropMu    sync.RWMutex
}

// NewBus creates a new event bus with the specified per-subscriber buffer size.
// Recommended: 4096 for moderate load, 8192 for high-throughput environments.
func NewBus(bufferSize int, logger *zap.Logger) *Bus {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	return &Bus{
		logger:      logger,
		bufferSize:  bufferSize,
		subscribers: make(map[string]chan *Event),
		dropped:     make(map[string]*atomic.Uint64),
	}
}

// Subscribe creates a new subscription channel with the given name.
// The subscriber receives events on the returned channel.
// The channel is closed when the bus is closed.
func (b *Bus) Subscribe(name string) <-chan *Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan *Event, b.bufferSize)
	b.subscribers[name] = ch

	b.dropMu.Lock()
	b.dropped[name] = &atomic.Uint64{}
	b.dropMu.Unlock()

	b.logger.Info("EventBus: subscriber registered",
		zap.String("name", name),
		zap.Int("buffer_size", b.bufferSize))

	return ch
}

// Publish sends an event to all subscribers.
// Non-blocking: if a subscriber's buffer is full, the event is dropped
// for that subscriber and a drop counter is incremented.
func (b *Bus) Publish(e *Event) {
	if b.closed.Load() {
		return
	}

	b.published.Add(1)

	b.mu.RLock()
	defer b.mu.RUnlock()

	for name, ch := range b.subscribers {
		select {
		case ch <- e:
			// delivered
		default:
			// subscriber buffer full — drop
			b.dropMu.RLock()
			if counter, ok := b.dropped[name]; ok {
				counter.Add(1)
			}
			b.dropMu.RUnlock()
		}
	}
}

// Close stops the bus and closes all subscriber channels.
// Any remaining events in subscriber buffers can still be consumed.
func (b *Bus) Close() {
	if b.closed.Swap(true) {
		return // already closed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for name, ch := range b.subscribers {
		close(ch)
		b.logger.Debug("EventBus: subscriber closed", zap.String("name", name))
	}
}

// Stats returns current bus statistics.
type Stats struct {
	Published           uint64
	DroppedBySubscriber map[string]uint64
	QueueDepth          map[string]int
}

// Stats returns a snapshot of bus metrics.
func (b *Bus) Stats() Stats {
	s := Stats{
		Published:           b.published.Load(),
		DroppedBySubscriber: make(map[string]uint64),
		QueueDepth:          make(map[string]int),
	}

	b.mu.RLock()
	for name, ch := range b.subscribers {
		s.QueueDepth[name] = len(ch)
	}
	b.mu.RUnlock()

	b.dropMu.RLock()
	for name, counter := range b.dropped {
		s.DroppedBySubscriber[name] = counter.Load()
	}
	b.dropMu.RUnlock()

	return s
}

// Dropped returns the total number of dropped events across all subscribers.
func (b *Bus) Dropped() uint64 {
	var total uint64
	b.dropMu.RLock()
	for _, counter := range b.dropped {
		total += counter.Load()
	}
	b.dropMu.RUnlock()
	return total
}

// Published returns the total number of published events.
func (b *Bus) Published() uint64 {
	return b.published.Load()
}
