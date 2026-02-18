// Package export provides the NATS JetStream exporter for the EventBus.
// Subscribes to events, JSON-encodes, batched publish to NATS for 1M msg/sec.
package export

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/event"
)

// NATSConfig holds NATS exporter settings.
type NATSConfig struct {
	URL           string        `yaml:"url"`
	Stream        string        `yaml:"stream"`
	Subject       string        `yaml:"subject"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// DefaultNATSConfig returns a lean default for small instances.
func DefaultNATSConfig() NATSConfig {
	return NATSConfig{
		URL:           constants.NATSDefaultURL,
		Stream:        constants.NATSStream,
		Subject:       constants.NATSSubject,
		BatchSize:     constants.NATSBatchSize,
		FlushInterval: constants.NATSFlushInterval,
	}
}

// wireEvent is the JSON wire format (flat, compact).
type wireEvent struct {
	Type      string             `json:"type"`
	Timestamp int64              `json:"ts"`
	PID       uint32             `json:"pid"`
	UID       uint32             `json:"uid"`
	Comm      string             `json:"comm"`
	Node      string             `json:"node"`
	Namespace string             `json:"ns"`
	Pod       string             `json:"pod"`
	Labels    map[string]string  `json:"l,omitempty"`
	Numerics  map[string]float64 `json:"n,omitempty"`
}

// NATSExporter publishes events to NATS JetStream.
type NATSExporter struct {
	cfg    NATSConfig
	logger *zap.Logger
	bus    *event.Bus
	events <-chan *event.Event

	nc *nats.Conn
	js jetstream.JetStream

	batch [][]byte
	mu    sync.Mutex
}

// NewNATSExporter creates a NATS exporter (Factory constructor).
func NewNATSExporter(cfg NATSConfig, bus *event.Bus, logger *zap.Logger) *NATSExporter {
	return &NATSExporter{
		cfg:    cfg,
		logger: logger,
		bus:    bus,
		batch:  make([][]byte, 0, cfg.BatchSize),
	}
}

func (e *NATSExporter) Name() string { return constants.ExporterNATS }

func (e *NATSExporter) Start(ctx context.Context) error {
	nc, err := nats.Connect(e.cfg.URL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			e.logger.Warn("NATS disconnected", zap.Error(err))
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			e.logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		return err
	}
	e.nc = nc

	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	e.js = js

	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      e.cfg.Stream,
		Subjects:  []string{e.cfg.Subject},
		Retention: jetstream.WorkQueuePolicy,
		MaxBytes:  constants.NATSStreamMaxBytes,
		Discard:   jetstream.DiscardOld,
		Storage:   jetstream.FileStorage,
	})
	if err != nil {
		return err
	}

	e.events = e.bus.Subscribe(constants.ExporterNATS)
	go e.flusher(ctx)

	e.logger.Info("NATS exporter started",
		zap.String("url", e.cfg.URL),
		zap.String("subject", e.cfg.Subject))

	for {
		select {
		case <-ctx.Done():
			e.flush()
			return ctx.Err()
		case evt, ok := <-e.events:
			if !ok {
				e.flush()
				return nil
			}
			e.enqueue(evt)
		}
	}
}

func (e *NATSExporter) Stop(_ context.Context) error {
	e.flush()
	if e.nc != nil {
		e.nc.Drain()
	}
	return nil
}

func (e *NATSExporter) enqueue(evt *event.Event) {
	w := wireEvent{
		Type:      evt.Type.String(),
		Timestamp: evt.Timestamp.UnixMilli(),
		PID:       evt.PID,
		UID:       evt.UID,
		Comm:      evt.Comm,
		Node:      evt.Node,
		Namespace: evt.Namespace,
		Pod:       evt.Pod,
		Labels:    evt.Labels,
		Numerics:  evt.Numeric,
	}
	data, err := json.Marshal(w)
	if err != nil {
		return
	}

	e.mu.Lock()
	e.batch = append(e.batch, data)
	full := len(e.batch) >= e.cfg.BatchSize
	e.mu.Unlock()

	if full {
		e.flush()
	}
}

func (e *NATSExporter) flush() {
	e.mu.Lock()
	if len(e.batch) == 0 {
		e.mu.Unlock()
		return
	}
	batch := e.batch
	e.batch = make([][]byte, 0, e.cfg.BatchSize)
	e.mu.Unlock()

	for _, data := range batch {
		e.nc.Publish(e.cfg.Subject, data)
	}
	e.nc.Flush()
}

func (e *NATSExporter) flusher(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.flush()
		}
	}
}
