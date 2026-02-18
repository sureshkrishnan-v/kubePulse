// Package cache provides a Redis client for KubePulse API caching + pub/sub.
package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
)

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	PoolSize int    `yaml:"pool_size"`
}

// DefaultRedisConfig returns lean defaults.
func DefaultRedisConfig() RedisConfig {
	return RedisConfig{
		Addr:     constants.RedisDefaultAddr,
		PoolSize: constants.RedisPoolSize,
	}
}

// Redis wraps go-redis with caching helpers.
type Redis struct {
	Client *redis.Client
	logger *zap.Logger
}

// NewRedis creates and pings a Redis connection.
func NewRedis(cfg RedisConfig, logger *zap.Logger) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		PoolSize: cfg.PoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	logger.Info("Redis connected", zap.String("addr", cfg.Addr))
	return &Redis{Client: client, logger: logger}, nil
}

// Get fetches a cached value by key.
func (r *Redis) Get(ctx context.Context, key string) (string, error) {
	return r.Client.Get(ctx, key).Result()
}

// Set stores a value with TTL.
func (r *Redis) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return r.Client.Set(ctx, key, value, ttl).Err()
}

// Publish sends a message to a pub/sub channel (for WebSocket live updates).
func (r *Redis) Publish(ctx context.Context, channel string, msg any) error {
	return r.Client.Publish(ctx, channel, msg).Err()
}

// Subscribe returns a pub/sub subscription channel.
func (r *Redis) Subscribe(ctx context.Context, channel string) *redis.PubSub {
	return r.Client.Subscribe(ctx, channel)
}

// Close closes the Redis connection.
func (r *Redis) Close() error {
	return r.Client.Close()
}
