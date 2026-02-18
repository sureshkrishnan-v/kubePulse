// Package fileio implements the file I/O latency monitoring probe.
// It hooks kprobe/kretprobe on vfs_read and vfs_write to measure I/O latency.
package fileio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// Operation type constants matching the BPF program.
const (
	OpRead  = 0
	OpWrite = 1
)

// Event represents a file I/O operation captured by the BPF program.
type Event struct {
	PID       uint32
	UID       uint32
	LatencyNs uint64
	Bytes     uint64
	Op        uint32 // 0=read, 1=write
	_         uint32 // padding
	Timestamp uint64
	Comm      [16]byte
}

// CommString returns the process name as a Go string.
func (e *Event) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n < 0 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// OpString returns "read" or "write" based on the operation type.
func (e *Event) OpString() string {
	if e.Op == OpWrite {
		return "write"
	}
	return "read"
}

// Handler is the callback signature for file I/O events.
type Handler func(Event)

// Probe implements probe.Probe for file I/O latency monitoring.
type Probe struct {
	logger  *zap.Logger
	handler Handler

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new file I/O probe.
func New(logger *zap.Logger, handler Handler) *Probe {
	return &Probe{logger: logger, handler: handler}
}

func (p *Probe) Name() string { return "fileio" }

func (p *Probe) Init() error {
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	// vfs_read kprobe + kretprobe
	kpRead, err := link.Kprobe("vfs_read", p.objs.KprobeVfsRead, nil)
	if err != nil {
		p.Close()
		return fmt.Errorf("attaching vfs_read kprobe: %w", err)
	}
	p.links = append(p.links, kpRead)

	krpRead, err := link.Kretprobe("vfs_read", p.objs.KretprobeVfsRead, nil)
	if err != nil {
		p.Close()
		return fmt.Errorf("attaching vfs_read kretprobe: %w", err)
	}
	p.links = append(p.links, krpRead)

	// vfs_write kprobe + kretprobe
	kpWrite, err := link.Kprobe("vfs_write", p.objs.KprobeVfsWrite, nil)
	if err != nil {
		p.Close()
		return fmt.Errorf("attaching vfs_write kprobe: %w", err)
	}
	p.links = append(p.links, kpWrite)

	krpWrite, err := link.Kretprobe("vfs_write", p.objs.KretprobeVfsWrite, nil)
	if err != nil {
		p.Close()
		return fmt.Errorf("attaching vfs_write kretprobe: %w", err)
	}
	p.links = append(p.links, krpWrite)

	p.reader, err = ringbuf.NewReader(p.objs.FileioEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return nil
}

func (p *Probe) Run(ctx context.Context) error {
	p.logger.Info("FileIO probe consumer started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			p.logger.Warn("Reading fileio event", zap.Error(err))
			continue
		}

		var event Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Parsing fileio event", zap.Error(err))
			continue
		}
		p.handler(event)
	}
}

func (p *Probe) Close() error {
	if p.reader != nil {
		p.reader.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
	return nil
}
