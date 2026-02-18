package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// OOMProbe consumes OOM kill events from the ring buffer.
type OOMProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(OOMEvent)
	dropped atomic.Uint64
}

func NewOOMProbe(r *ringbuf.Reader, l *zap.Logger, h func(OOMEvent)) *OOMProbe {
	return &OOMProbe{reader: r, logger: l, handler: h}
}

func (p *OOMProbe) Run(ctx context.Context) error {
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
		var event OOMEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse OOM event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *OOMProbe) DroppedCount() uint64 { return p.dropped.Load() }
