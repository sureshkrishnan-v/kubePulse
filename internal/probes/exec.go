package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// ExecProbe consumes process exec events from the ring buffer.
type ExecProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(ExecEvent)
	dropped atomic.Uint64
}

func NewExecProbe(r *ringbuf.Reader, l *zap.Logger, h func(ExecEvent)) *ExecProbe {
	return &ExecProbe{reader: r, logger: l, handler: h}
}

func (p *ExecProbe) Run(ctx context.Context) error {
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
		var event ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse exec event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *ExecProbe) DroppedCount() uint64 { return p.dropped.Load() }
