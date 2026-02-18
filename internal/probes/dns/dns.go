// Package dns implements the DNS query monitoring module.
package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
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
	DAddr     uint32
	DPort     uint16
	Pad1      uint16
	QName     [constants.QNameSize]byte
	Timestamp uint64
	Comm      [constants.CommSize]byte
}

// Module implements probe.Module for DNS query monitoring.
type Module struct {
	deps   probe.Dependencies
	logger *zap.Logger

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new DNS module instance (Factory constructor).
func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return constants.ModuleDNS }

func (m *Module) Init(_ context.Context, deps probe.Dependencies) error {
	m.deps = deps
	m.logger = deps.Logger

	if err := loadBpfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	kp, err := link.Kprobe("udp_sendmsg", m.objs.KprobeUdpSendmsg, nil)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
	}
	m.links = append(m.links, kp)

	m.reader, err = ringbuf.NewReader(m.objs.DnsEvents)
	if err != nil {
		m.Stop(context.Background())
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.logger.Info("DNS module consumer started")
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
			m.logger.Warn("Reading DNS event", zap.Error(err))
			continue
		}

		var raw rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			m.logger.Warn("Parsing DNS event", zap.Error(err))
			continue
		}

		e := event.Acquire()
		e.Type = event.TypeDNS
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

		qname := bpfutil.QNameString(raw.QName)
		e.SetLabel(constants.KeyQName, qname)
		e.SetLabel(constants.KeyDomain, TruncateDomain(qname))

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

// TruncateDomain reduces a FQDN to its top-level registered domain
// for low-cardinality Prometheus labels.
func TruncateDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
