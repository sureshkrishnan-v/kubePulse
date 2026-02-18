package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// RetransmitProbe consumes TCP retransmission events from the ring buffer.
type RetransmitProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(RetransmitEvent)
	dropped atomic.Uint64
}

func NewRetransmitProbe(r *ringbuf.Reader, l *zap.Logger, h func(RetransmitEvent)) *RetransmitProbe {
	return &RetransmitProbe{reader: r, logger: l, handler: h}
}

func (p *RetransmitProbe) Run(ctx context.Context) error {
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
		var event RetransmitEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse retransmit event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *RetransmitProbe) DroppedCount() uint64 { return p.dropped.Load() }
