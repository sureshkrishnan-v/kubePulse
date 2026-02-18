// Package fileio implements the file I/O latency monitoring module.
package fileio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/bpfutil"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
	"github.com/sureshkrishnan-v/kubePulse/internal/probe"
)

type rawEvent struct {
	PID       uint32
	UID       uint32
	LatencyNs uint64
	Bytes     uint64
	Op        uint32 // 0=read, 1=write
	Pad1      uint32
	Timestamp uint64
	Comm      [constants.CommSize]byte
}

// Module implements probe.Module for file I/O latency monitoring.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new FileIO module instance (Factory constructor).
func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return constants.ModuleFileIO }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger
	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	kpRead, err := link.Kprobe("vfs_read", m.objs.KprobeVfsRead, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching vfs_read kprobe: %w", err)
	}
	m.links = append(m.links, kpRead)

	krpRead, err := link.Kretprobe("vfs_read", m.objs.KretprobeVfsRead, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching vfs_read kretprobe: %w", err)
	}
	m.links = append(m.links, krpRead)

	kpWrite, err := link.Kprobe("vfs_write", m.objs.KprobeVfsWrite, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching vfs_write kprobe: %w", err)
	}
	m.links = append(m.links, kpWrite)

	krpWrite, err := link.Kretprobe("vfs_write", m.objs.KretprobeVfsWrite, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching vfs_write kretprobe: %w", err)
	}
	m.links = append(m.links, krpWrite)

	m.reader, err = ringbuf.NewReader(m.objs.FileioEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("FileIO module consumer started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			m.logger.Warn("Reading fileio event", zap.Error(err))
			continue
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing fileio event", zap.Error(err))
			continue
		}
		e := event.Acquire()
		e.Type = event.TypeFileIO
		e.Timestamp = time.Now()
		e.PID = raw.PID
		e.UID = raw.UID
		e.Comm = bpfutil.CommString(raw.Comm)
		e.Node = m.deps.NodeName
		if m.deps.Metadata != nil {
			if meta, found := m.deps.Metadata.Lookup(raw.PID); found {
				e.Namespace = meta.Namespace
				e.Pod = meta.PodName
			}
		}
		op := constants.FileOpRead
		if raw.Op == 1 {
			op = constants.FileOpWrite
		}
		e.SetLabel(constants.KeyOp, op)
		e.SetNumeric(constants.KeyLatencySec, float64(raw.LatencyNs)/constants.NsPerSecond)
		e.SetNumeric(constants.KeyBytes, float64(raw.Bytes))
		m.deps.EventBus.Publish(e)
	}
}

func (m *Module) Stop(_ context.Context) error {
	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
	return nil
}
