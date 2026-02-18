// Package storage provides ClickHouse batch insert client for KubePulse.
// Optimized for 1M inserts/sec via async batch writes.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
)

// ClickHouseConfig holds connection settings.
type ClickHouseConfig struct {
	DSN      string `yaml:"dsn"`
	MaxConns int    `yaml:"max_conns"`
}

// DefaultClickHouseConfig returns lean defaults.
func DefaultClickHouseConfig() ClickHouseConfig {
	return ClickHouseConfig{
		DSN:      constants.ClickHouseDefaultDSN,
		MaxConns: constants.ClickHouseMaxConns,
	}
}

// ClickHouse is the batch-insert client.
type ClickHouse struct {
	conn   driver.Conn
	logger *zap.Logger
}

// NewClickHouse creates and pings a ClickHouse connection.
func NewClickHouse(cfg ClickHouseConfig, logger *zap.Logger) (*ClickHouse, error) {
	opts, err := clickhouse.ParseDSN(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}
	opts.MaxOpenConns = cfg.MaxConns
	opts.MaxIdleConns = cfg.MaxConns
	opts.ConnMaxLifetime = 10 * time.Minute

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	logger.Info("ClickHouse connected", zap.String("dsn", cfg.DSN))
	return &ClickHouse{conn: conn, logger: logger}, nil
}

// EventRow is one row for batch insert.
type EventRow struct {
	Timestamp time.Time
	Type      string
	PID       uint32
	UID       uint32
	Comm      string
	Node      string
	Namespace string
	Pod       string
	Labels    map[string]string
	Numerics  map[string]float64
}

// InsertBatch inserts a batch of events into ClickHouse.
// Uses native batch protocol for maximum throughput.
func (ch *ClickHouse) InsertBatch(ctx context.Context, rows []EventRow) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := ch.conn.PrepareBatch(ctx,
		"INSERT INTO kubepulse.events (timestamp, event_type, pid, uid, comm, node, namespace, pod, labels, numerics)")
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp,
			r.Type,
			r.PID,
			r.UID,
			r.Comm,
			r.Node,
			r.Namespace,
			r.Pod,
			r.Labels,
			r.Numerics,
		); err != nil {
			return fmt.Errorf("append row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}

	ch.logger.Debug("Batch inserted", zap.Int("rows", len(rows)))
	return nil
}

// Close closes the ClickHouse connection.
func (ch *ClickHouse) Close() error {
	return ch.conn.Close()
}

// Query executes a query and returns rows. Used by the API layer.
func (ch *ClickHouse) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return ch.conn.Query(ctx, query, args...)
}

// QueryRow executes a query returning a single row.
func (ch *ClickHouse) QueryRow(ctx context.Context, query string, args ...any) driver.Row {
	return ch.conn.QueryRow(ctx, query, args...)
}
