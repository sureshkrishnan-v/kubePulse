// API server for KubePulse — serves frontend dashboard data.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/api"
	"github.com/sureshkrishnan-v/kubePulse/internal/cache"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/storage"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	logger.Info("KubePulse API starting")

	// ClickHouse
	chCfg := storage.DefaultClickHouseConfig()
	if dsn := os.Getenv("CLICKHOUSE_DSN"); dsn != "" {
		chCfg.DSN = dsn
	}
	ch, err := storage.NewClickHouse(chCfg, logger)
	if err != nil {
		logger.Fatal("ClickHouse connection failed", zap.Error(err))
	}
	defer ch.Close()

	// Redis
	rCfg := cache.DefaultRedisConfig()
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rCfg.Addr = addr
	}
	redis, err := cache.NewRedis(rCfg, logger)
	if err != nil {
		logger.Fatal("Redis connection failed", zap.Error(err))
	}
	defer redis.Close()

	// API Server
	addr := constants.APIDefaultAddr
	if a := os.Getenv("API_ADDR"); a != "" {
		addr = a
	}

	srv := api.NewServer(addr, ch, redis, logger)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := srv.Start(); err != nil {
			logger.Fatal("API server error", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("Shutting down API server")
	srv.Stop()
}
