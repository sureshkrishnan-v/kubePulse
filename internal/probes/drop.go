package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// DropProbe consumes packet drop events from the ring buffer.
type DropProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(DropEvent)
	dropped atomic.Uint64
}

func NewDropProbe(r *ringbuf.Reader, l *zap.Logger, h func(DropEvent)) *DropProbe {
	return &DropProbe{reader: r, logger: l, handler: h}
}

func (p *DropProbe) Run(ctx context.Context) error {
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
		var event DropEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse drop event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *DropProbe) DroppedCount() uint64 { return p.dropped.Load() }
