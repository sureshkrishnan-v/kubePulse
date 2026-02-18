package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// FileIOProbe consumes file I/O latency events from the ring buffer.
type FileIOProbe struct {
	reader  *ringbuf.Reader
	logger  *zap.Logger
	handler func(FileIOEvent)
	dropped atomic.Uint64
}

func NewFileIOProbe(r *ringbuf.Reader, l *zap.Logger, h func(FileIOEvent)) *FileIOProbe {
	return &FileIOProbe{reader: r, logger: l, handler: h}
}

func (p *FileIOProbe) Run(ctx context.Context) error {
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
		var event FileIOEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Failed to parse file I/O event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *FileIOProbe) DroppedCount() uint64 { return p.dropped.Load() }
