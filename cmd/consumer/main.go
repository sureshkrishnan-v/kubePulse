// Consumer service — reads events from NATS JetStream and batch-inserts into ClickHouse.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/consumer"
	"github.com/sureshkrishnan-v/kubePulse/internal/storage"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	logger.Info("KubePulse consumer starting")

	// ClickHouse
	chCfg := storage.DefaultClickHouseConfig()
	if dsn := os.Getenv("CLICKHOUSE_DSN"); dsn != "" {
		chCfg.DSN = dsn
	}
	ch, err := storage.NewClickHouse(chCfg, logger)
	if err != nil {
		logger.Fatal("Failed to connect to ClickHouse", zap.Error(err))
	}
	defer ch.Close()

	// Consumer
	cfg := consumer.DefaultConfig()
	if url := os.Getenv("NATS_URL"); url != "" {
		cfg.NATSURL = url
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := consumer.New(cfg, ch, logger)
	if err := c.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Fatal("Consumer error", zap.Error(err))
	}

	logger.Info("Consumer stopped")
}
