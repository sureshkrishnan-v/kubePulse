package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// RSTProbe consumes TCP RST events from the ring buffer.
type RSTProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(RSTEvent)
	dropped atomic.Uint64
}

func NewRSTProbe(r *ringbuf.Reader, l *zap.Logger, h func(RSTEvent)) *RSTProbe {
	return &RSTProbe{reader: r, logger: l, handler: h}
}

func (p *RSTProbe) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		record, err := p.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			p.dropped.Add(1)
			continue
		}
		var event RSTEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse RST event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *RSTProbe) DroppedCount() uint64 { return p.dropped.Load() }
