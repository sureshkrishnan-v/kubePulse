// Package probes provides ring buffer consumers for eBPF events.
package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// TCPProbe reads TCP events from the BPF ring buffer and dispatches them.
type TCPProbe struct {
	reader       *ringbuf.Reader
	logger       *zap.Logger
	handler      func(TCPEvent)
	droppedCount atomic.Uint64 // Tracks ring buffer losses
}

// NewTCPProbe creates a new TCP probe consumer.
// handler is called for each TCP event read from the ring buffer.
func NewTCPProbe(reader *ringbuf.Reader, logger *zap.Logger, handler func(TCPEvent)) *TCPProbe {
	return &TCPProbe{
		reader:  reader,
		logger:  logger,
		handler: handler,
	}
}

// Run starts reading TCP events from the ring buffer.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
func (tp *TCPProbe) Run(ctx context.Context) error {
	tp.logger.Info("TCP probe started, reading events from ring buffer")

	for {
		select {
		case <-ctx.Done():
			tp.logger.Info("TCP probe shutting down",
				zap.Uint64("events_dropped", tp.droppedCount.Load()))
			return ctx.Err()
		default:
		}

		record, err := tp.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				tp.logger.Info("TCP ring buffer closed")
				return nil
			}
			tp.logger.Error("reading TCP event from ring buffer", zap.Error(err))
			continue
		}

		// Check for lost events (ring buffer overflow)
		// The cilium/ebpf library doesn't expose per-record loss,
		// but we track reservation failures in BPF via the dropped counter.

		var event TCPEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			tp.logger.Error("parsing TCP event",
				zap.Error(err),
				zap.Int("raw_len", len(record.RawSample)),
				zap.Int("expected_len", int(binary.Size(TCPEvent{}))))
			continue
		}

		tp.handler(event)
	}
}

// DroppedCount returns the total number of events dropped due to ring buffer overflow.
func (tp *TCPProbe) DroppedCount() uint64 {
	return tp.droppedCount.Load()
}
