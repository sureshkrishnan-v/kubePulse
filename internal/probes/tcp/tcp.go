// Package tcp implements the TCP connection latency module.
package tcp

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

// rawEvent is the BPF-side event struct (byte-identical to C definition).
type rawEvent struct {
	PID       uint32
	UID       uint32
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	LatencyNs uint64
	Timestamp uint64
	Comm      [constants.CommSize]byte
}

// Module implements probe.Module for TCP connection latency monitoring.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new TCP module instance (Factory constructor).
func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return constants.ModuleTCP }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger

	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	kpConnect, err := link.Kprobe("tcp_connect", m.objs.KprobeTcpConnect, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching tcp_connect kprobe: %w", err)
	}
	m.links = append(m.links, kpConnect)

	kpClose, err := link.Kprobe("tcp_close", m.objs.KprobeTcpClose, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching tcp_close kprobe: %w", err)
	}
	m.links = append(m.links, kpClose)

	m.reader, err = ringbuf.NewReader(m.objs.TcpEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("TCP module consumer started")
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
			m.logger.Warn("Reading TCP event", zap.Error(err))
			continue
		}

		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing TCP event", zap.Error(err))
			continue
		}

		e := event.Acquire()
		e.Type = event.TypeTCP
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

		e.SetLabel(constants.KeySrc, fmt.Sprintf("%s:%d", bpfutil.FormatIPv4(raw.SAddr), raw.SPort))
		e.SetLabel(constants.KeyDst, fmt.Sprintf("%s:%d", bpfutil.FormatIPv4(raw.DAddr), raw.DPort))
		e.SetNumeric(constants.KeyLatencySec, float64(raw.LatencyNs)/constants.NsPerSecond)
		e.SetNumeric(constants.KeyLatencyNs, float64(raw.LatencyNs))

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
