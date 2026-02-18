// Package tcp implements the TCP connection latency module.
// It hooks tcp_connect and tcp_close kprobes to measure connection setup time.
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
	Comm      [16]byte
}

// Module implements probe.Module for TCP connection latency monitoring.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

func (m *Module) Name() string { return "tcp" }

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

		// Enrich and publish to EventBus
		e := event.Acquire()
		e.Type = event.TypeTCP
		e.Timestamp = time.Now()
		e.PID = raw.PID
		e.UID = raw.UID
		e.Comm = commString(raw.Comm)
		e.Node = m.deps.NodeName

		// Resolve K8s metadata
		if m.deps.Metadata != nil {
			if meta, found := m.deps.Metadata.Lookup(raw.PID); found {
				e.Namespace = meta.Namespace
				e.Pod = meta.PodName
			}
		}

		// Type-specific fields
		e.SetLabel("src", fmt.Sprintf("%s:%d", FormatIPv4(raw.SAddr), raw.SPort))
		e.SetLabel("dst", fmt.Sprintf("%s:%d", FormatIPv4(raw.DAddr), raw.DPort))
		e.SetNumeric("latency_sec", float64(raw.LatencyNs)/1e9)
		e.SetNumeric("latency_ns", float64(raw.LatencyNs))

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

// FormatIPv4 converts a uint32 IPv4 address to dotted-decimal string.
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func commString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = len(comm)
	}
	return string(comm[:n])
}
