// Package drop implements the packet drop detector probe.
// It hooks tracepoint/skb/kfree_skb to detect dropped packets with reasons.
package drop

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

// Event represents a packet drop event captured by the BPF program.
type Event struct {
	PID        uint32
	DropReason uint32
	Protocol   uint16
	_          uint16 // padding
	_pad2      uint32 // padding
	Location   uint64 // kernel function address
	Timestamp  uint64
	Comm       [16]byte
}

// CommString returns the process name as a Go string.
func (e *Event) CommString() string {
	n := bytes.IndexByte(e.Comm[:], 0)
	if n < 0 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// DropReasonString returns a human-readable drop reason string.
func (e *Event) DropReasonString() string {
	reasons := map[uint32]string{
		2:  "NOT_SPECIFIED",
		3:  "NO_SOCKET",
		4:  "PKT_TOO_SMALL",
		5:  "TCP_CSUM",
		6:  "SOCKET_FILTER",
		7:  "UDP_CSUM",
		16: "NETFILTER_DROP",
		17: "OTHERHOST",
		27: "QUEUE_PURGE",
	}
	if s, ok := reasons[e.DropReason]; ok {
		return s
	}
	return fmt.Sprintf("REASON_%d", e.DropReason)
}

// Handler is the callback signature for drop events.
type Handler func(Event)

// Probe implements probe.Probe for packet drop monitoring.
type Probe struct {
	logger  *zap.Logger
	handler Handler

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new packet drop probe.
func New(logger *zap.Logger, handler Handler) *Probe {
	return &Probe{logger: logger, handler: handler}
}

func (p *Probe) Name() string { return "drop" }

func (p *Probe) Init() error {
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	tp, err := link.Tracepoint("skb", "kfree_skb", p.objs.TracepointKfreeSkb, nil)
	if err != nil {
		p.Close()
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	p.links = append(p.links, tp)

	p.reader, err = ringbuf.NewReader(p.objs.DropEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return nil
}

func (p *Probe) Run(ctx context.Context) error {
	p.logger.Info("Drop probe consumer started")
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
			p.logger.Warn("Reading drop event", zap.Error(err))
			continue
		}

		var event Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			p.logger.Warn("Parsing drop event", zap.Error(err))
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
