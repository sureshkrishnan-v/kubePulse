// Package retransmit implements the TCP retransmission detector module.
package retransmit

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

	"github.com/sureshkrishnan-v/kubePulse/internal/event"
	"github.com/sureshkrishnan-v/kubePulse/internal/probe"
)

type rawEvent struct {
	PID       uint32
	UID       uint32
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	State     uint32
	_         uint32
	Timestamp uint64
	Comm      [16]byte
}

type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

func (m *Module) Name() string { return "retransmit" }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger
	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", m.objs.TracepointTcpRetransmit, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	m.links = append(m.links, tp)
	m.reader, err = ringbuf.NewReader(m.objs.RetransmitEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("Retransmit module consumer started")
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
			m.logger.Warn("Reading retransmit event", zap.Error(err))
			continue
		}
		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing retransmit event", zap.Error(err))
			continue
		}
		e := event.Acquire()
		e.Type = event.TypeRetransmit
		e.Timestamp = time.Now()
		e.PID = raw.PID
		e.UID = raw.UID
		e.Comm = commString(raw.Comm)
		e.Node = m.deps.NodeName
		if m.deps.Metadata != nil {
			if meta, found := m.deps.Metadata.Lookup(raw.PID); found {
				e.Namespace = meta.Namespace
				e.Pod = meta.PodName
			}
		}
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

func commString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = len(comm)
	}
	return string(comm[:n])
}
