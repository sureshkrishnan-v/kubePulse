// Package consumer implements the NATS→ClickHouse event pipeline.
// Pull-based batching: consumes from NATS JetStream, accumulates events,
// flushes to ClickHouse in optimized batches (time-or-size triggered).
package consumer

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/storage"
)

// Config holds consumer settings.
type Config struct {
	NATSURL       string        `yaml:"nats_url"`
	Stream        string        `yaml:"stream"`
	Subject       string        `yaml:"subject"`
	ConsumerName  string        `yaml:"consumer_name"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Workers       int           `yaml:"workers"`
}

// DefaultConfig returns lean defaults.
func DefaultConfig() Config {
	return Config{
		NATSURL:       constants.NATSDefaultURL,
		Stream:        constants.NATSStream,
		Subject:       constants.NATSSubject,
		ConsumerName:  "kubepulse-consumer",
		BatchSize:     constants.ClickHouseBatchSize,
		FlushInterval: constants.ClickHouseFlushInterval,
		Workers:       constants.DefaultWorkerPoolSize,
	}
}

// wireEvent matches the NATS exporter wire format.
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

// Consumer reads from NATS and batch-inserts into ClickHouse.
type Consumer struct {
	cfg    Config
	ch     *storage.ClickHouse
	logger *zap.Logger

	mu    sync.Mutex
	batch []storage.EventRow
}

// New creates a consumer instance.
func New(cfg Config, ch *storage.ClickHouse, logger *zap.Logger) *Consumer {
	return &Consumer{
		cfg:    cfg,
		ch:     ch,
		logger: logger,
		batch:  make([]storage.EventRow, 0, cfg.BatchSize),
	}
}

// Run starts consuming from NATS JetStream and flushing to ClickHouse.
// Blocks until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	nc, err := nats.Connect(c.cfg.NATSURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return err
	}
	defer nc.Drain()

	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}

	// Create durable consumer
	cons, err := js.CreateOrUpdateConsumer(ctx, c.cfg.Stream, jetstream.ConsumerConfig{
		Durable:       c.cfg.ConsumerName,
		FilterSubject: c.cfg.Subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxAckPending: c.cfg.BatchSize * 2,
	})
	if err != nil {
		return err
	}

	// Start flush ticker
	go c.flusher(ctx)

	c.logger.Info("Consumer started",
		zap.String("stream", c.cfg.Stream),
		zap.Int("batch_size", c.cfg.BatchSize))

	// Consume messages
	_, err = cons.Consume(func(msg jetstream.Msg) {
		var w wireEvent
		if err := json.Unmarshal(msg.Data(), &w); err != nil {
			c.logger.Warn("Failed to decode event", zap.Error(err))
			msg.Nak()
			return
		}

		row := storage.EventRow{
			Timestamp: time.UnixMilli(w.Timestamp),
			Type:      w.Type,
			PID:       w.PID,
			UID:       w.UID,
			Comm:      w.Comm,
			Node:      w.Node,
			Namespace: w.Namespace,
			Pod:       w.Pod,
			Labels:    w.Labels,
			Numerics:  w.Numerics,
		}

		c.mu.Lock()
		c.batch = append(c.batch, row)
		full := len(c.batch) >= c.cfg.BatchSize
		c.mu.Unlock()

		msg.Ack()

		if full {
			c.flush(ctx)
		}
	})
	if err != nil {
		return err
	}

	<-ctx.Done()
	c.flush(ctx)
	return nil
}

// flush writes accumulated rows to ClickHouse.
func (c *Consumer) flush(ctx context.Context) {
	c.mu.Lock()
	if len(c.batch) == 0 {
		c.mu.Unlock()
		return
	}
	batch := c.batch
	c.batch = make([]storage.EventRow, 0, c.cfg.BatchSize)
	c.mu.Unlock()

	if err := c.ch.InsertBatch(ctx, batch); err != nil {
		c.logger.Error("ClickHouse batch insert failed",
			zap.Error(err), zap.Int("rows", len(batch)))
		return
	}
	c.logger.Info("Flushed to ClickHouse", zap.Int("rows", len(batch)))
}

func (c *Consumer) flusher(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flush(ctx)
		}
	}
}
