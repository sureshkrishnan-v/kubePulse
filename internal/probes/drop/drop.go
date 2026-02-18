// Package drop implements the packet drop detector module.
package drop

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
	PID        uint32
	DropReason uint32
	Protocol   uint16
	Pad1       uint16
	Pad2       uint32
	Location   uint64
	Timestamp  uint64
	Comm       [constants.CommSize]byte
}

// Module implements probe.Module for packet drop detection.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new Drop module instance (Factory constructor).
func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return constants.ModuleDrop }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger
	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	tp, err := link.Tracepoint("skb", "kfree_skb", m.objs.TracepointKfreeSkb, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	m.links = append(m.links, tp)
	m.reader, err = ringbuf.NewReader(m.objs.DropEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("Drop module consumer started")
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
			m.logger.Warn("Reading drop event", zap.Error(err))
			continue
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing drop event", zap.Error(err))
			continue
		}
		e := event.Acquire()
		e.Type = event.TypeDrop
		e.Timestamp = time.Now()
		e.PID = raw.PID
		e.Comm = bpfutil.CommString(raw.Comm)
		e.Node = m.deps.NodeName
		e.SetLabel(constants.KeyReason, bpfutil.DropReasonString(raw.DropReason))
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
