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

// DNSProbe reads DNS events from the BPF ring buffer and dispatches them.
type DNSProbe struct {
	reader       *ringbuf.Reader
	logger       *zap.Logger
	handler      func(DNSEvent)
	droppedCount atomic.Uint64
}

// NewDNSProbe creates a new DNS probe consumer.
// handler is called for each DNS event read from the ring buffer.
func NewDNSProbe(reader *ringbuf.Reader, logger *zap.Logger, handler func(DNSEvent)) *DNSProbe {
	return &DNSProbe{
		reader:  reader,
		logger:  logger,
		handler: handler,
	}
}

// Run starts reading DNS events from the ring buffer.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
func (dp *DNSProbe) Run(ctx context.Context) error {
	dp.logger.Info("DNS probe started, reading events from ring buffer")

	for {
		select {
		case <-ctx.Done():
			dp.logger.Info("DNS probe shutting down",
				zap.Uint64("events_dropped", dp.droppedCount.Load()))
			return ctx.Err()
		default:
		}

		record, err := dp.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				dp.logger.Info("DNS ring buffer closed")
				return nil
			}
			dp.logger.Error("reading DNS event from ring buffer", zap.Error(err))
			continue
		}

		var event DNSEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			dp.logger.Error("parsing DNS event",
				zap.Error(err),
				zap.Int("raw_len", len(record.RawSample)),
				zap.Int("expected_len", int(binary.Size(DNSEvent{}))))
			continue
		}

		dp.handler(event)
	}
}

// DroppedCount returns the total number of DNS events dropped.
func (dp *DNSProbe) DroppedCount() uint64 {
	return dp.droppedCount.Load()
}
