// Package exec implements the process execution monitoring module.
package exec

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
	OldPID    uint32
	Pad1      uint32
	Timestamp uint64
	Comm      [constants.CommSize]byte
	Filename  [constants.FilenameSize]byte
}

// Module implements probe.Module for process execution monitoring.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new Exec module instance (Factory constructor).
func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return constants.ModuleExec }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger
	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	tp, err := link.Tracepoint("sched", "sched_process_exec", m.objs.TracepointSchedProcessExec, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	m.links = append(m.links, tp)
	m.reader, err = ringbuf.NewReader(m.objs.ExecEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("Exec module consumer started")
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
			m.logger.Warn("Reading exec event", zap.Error(err))
			continue
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing exec event", zap.Error(err))
			continue
		}
		e := event.Acquire()
		e.Type = event.TypeExec
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
		e.SetLabel(constants.KeyFilename, bpfutil.FilenameString(raw.Filename))
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
