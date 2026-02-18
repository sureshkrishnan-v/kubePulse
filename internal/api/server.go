// Package api provides the KubePulse HTTP API server.
// Uses Fiber v2 (zero-alloc, fasthttp-based) for max throughput.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"go.uber.org/zap"

	"github.com/sureshkrishnan-v/kubePulse/internal/cache"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
	"github.com/sureshkrishnan-v/kubePulse/internal/storage"
)

// Server is the HTTP API server.
type Server struct {
	app    *fiber.App
	ch     *storage.ClickHouse
	redis  *cache.Redis
	logger *zap.Logger
	addr   string
}

// NewServer creates a Fiber API server with all routes.
func NewServer(addr string, ch *storage.ClickHouse, redis *cache.Redis, logger *zap.Logger) *Server {
	app := fiber.New(fiber.Config{
		Prefork:       false,
		StrictRouting: false,
		ReadTimeout:   constants.HTTPReadTimeout,
		WriteTimeout:  constants.HTTPWriteTimeout,
		IdleTimeout:   constants.HTTPIdleTimeout,
	})

	s := &Server{
		app:    app,
		ch:     ch,
		redis:  redis,
		logger: logger,
		addr:   addr,
	}

	// Middleware
	app.Use(recover.New())
	app.Use(fiberlogger.New(fiberlogger.Config{Format: "${time} ${status} ${method} ${path} ${latency}\n"}))
	app.Use(cors.New(cors.Config{AllowOrigins: "*"}))
	app.Use(compress.New())
	app.Use(limiter.New(limiter.Config{
		Max:        constants.APIRateLimit,
		Expiration: time.Second,
	}))

	// Routes
	v1 := app.Group("/api/v1")
	v1.Get("/events", s.handleEvents)
	v1.Get("/events/types", s.handleEventTypes)
	v1.Get("/metrics/overview", s.handleOverview)
	v1.Get("/metrics/:type", s.handleMetricsByType)
	v1.Get("/topology", s.handleTopology)

	// WebSocket for live events
	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	app.Get("/ws/events", websocket.New(s.handleWS))

	// Health
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.SendString("ok") })

	return s
}

// Start begins listening. Blocks until shutdown.
func (s *Server) Start() error {
	s.logger.Info("API server listening", zap.String("addr", s.addr))
	return s.app.Listen(s.addr)
}

// Stop gracefully shuts down.
func (s *Server) Stop() error {
	return s.app.Shutdown()
}

// ─── Handlers ────────────────────────────────────────────────────

// handleEvents returns paginated events from ClickHouse.
func (s *Server) handleEvents(c *fiber.Ctx) error {
	limit := min(c.QueryInt("limit", constants.APIDefaultPageSize), constants.APIMaxPageSize)
	offset := c.QueryInt("offset", 0)
	eventType := c.Query("type")
	namespace := c.Query("namespace")
	since := c.Query("since") // ISO8601

	// Build query
	query := "SELECT timestamp, event_type, pid, comm, node, namespace, pod, labels, numerics FROM kubepulse.events WHERE 1=1"
	args := make([]any, 0)

	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if namespace != "" {
		query += " AND namespace = ?"
		args = append(args, namespace)
	}
	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err == nil {
			query += " AND timestamp >= ?"
			args = append(args, t)
		}
	}

	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.ch.Query(c.Context(), query, args...)
	if err != nil {
		s.logger.Error("Query failed", zap.Error(err))
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	var events []fiber.Map
	for rows.Next() {
		var (
			ts       time.Time
			evtType  string
			pid      uint32
			comm     string
			node     string
			ns       string
			pod      string
			labels   map[string]string
			numerics map[string]float64
		)
		if err := rows.Scan(&ts, &evtType, &pid, &comm, &node, &ns, &pod, &labels, &numerics); err != nil {
			continue
		}
		events = append(events, fiber.Map{
			"timestamp": ts,
			"type":      evtType,
			"pid":       pid,
			"comm":      comm,
			"node":      node,
			"namespace": ns,
			"pod":       pod,
			"labels":    labels,
			"numerics":  numerics,
		})
	}

	return c.JSON(fiber.Map{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}

// handleEventTypes returns distinct event types.
func (s *Server) handleEventTypes(c *fiber.Ctx) error {
	cacheKey := "event_types"
	if cached, err := s.redis.Get(c.Context(), cacheKey); err == nil {
		c.Set("X-Cache", "HIT")
		return c.SendString(cached)
	}

	rows, err := s.ch.Query(c.Context(),
		"SELECT event_type, count() AS cnt FROM kubepulse.events GROUP BY event_type ORDER BY cnt DESC")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	var types []fiber.Map
	for rows.Next() {
		var t string
		var cnt uint64
		if err := rows.Scan(&t, &cnt); err != nil {
			continue
		}
		types = append(types, fiber.Map{"type": t, "count": cnt})
	}

	result, _ := json.Marshal(fiber.Map{"types": types})
	s.redis.Set(c.Context(), cacheKey, string(result), constants.RedisCacheTTL)
	c.Set("X-Cache", "MISS")
	return c.Send(result)
}

// handleOverview returns dashboard summary metrics.
func (s *Server) handleOverview(c *fiber.Ctx) error {
	cacheKey := "overview"
	if cached, err := s.redis.Get(c.Context(), cacheKey); err == nil {
		c.Set("X-Cache", "HIT")
		return c.SendString(cached)
	}

	row := s.ch.QueryRow(c.Context(), `
		SELECT 
			count() AS total_events,
			countIf(event_type = 'tcp') AS tcp_events,
			countIf(event_type = 'dns') AS dns_events,
			countIf(event_type = 'oom') AS oom_events,
			countIf(event_type = 'drop') AS drop_events,
			avg(numerics['latency_sec']) AS avg_latency
		FROM kubepulse.events 
		WHERE timestamp >= now() - INTERVAL 1 HOUR
	`)

	var total, tcpN, dnsN, oomN, dropN uint64
	var avgLat float64
	if err := row.Scan(&total, &tcpN, &dnsN, &oomN, &dropN, &avgLat); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}

	result := fiber.Map{
		"total_events":    total,
		"tcp_events":      tcpN,
		"dns_events":      dnsN,
		"oom_events":      oomN,
		"drop_events":     dropN,
		"avg_latency_sec": avgLat,
		"window":          "1h",
	}

	data, _ := json.Marshal(result)
	s.redis.Set(c.Context(), cacheKey, string(data), constants.RedisCacheTTL)
	c.Set("X-Cache", "MISS")
	return c.JSON(result)
}

// handleMetricsByType returns time-series metrics for a specific event type.
func (s *Server) handleMetricsByType(c *fiber.Ctx) error {
	evtType := c.Params("type")
	window := c.Query("window", "1h")

	cacheKey := "metrics:" + evtType + ":" + window
	if cached, err := s.redis.Get(c.Context(), cacheKey); err == nil {
		c.Set("X-Cache", "HIT")
		return c.SendString(cached)
	}

	query := `
		SELECT 
			toStartOfMinute(timestamp) AS minute,
			count() AS cnt,
			avg(numerics['latency_sec']) AS avg_latency,
			quantile(0.99)(numerics['latency_sec']) AS p99_latency
		FROM kubepulse.events
		WHERE event_type = ? AND timestamp >= now() - INTERVAL ` + sanitizeInterval(window) + `
		GROUP BY minute
		ORDER BY minute
	`

	rows, err := s.ch.Query(c.Context(), query, evtType)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	var series []fiber.Map
	for rows.Next() {
		var minute time.Time
		var cnt uint64
		var avgLat, p99Lat float64
		if err := rows.Scan(&minute, &cnt, &avgLat, &p99Lat); err != nil {
			continue
		}
		series = append(series, fiber.Map{
			"time":        minute,
			"count":       cnt,
			"avg_latency": avgLat,
			"p99_latency": p99Lat,
		})
	}

	result, _ := json.Marshal(fiber.Map{"type": evtType, "series": series})
	s.redis.Set(c.Context(), cacheKey, string(result), constants.RedisCacheTTL)
	c.Set("X-Cache", "MISS")
	return c.Send(result)
}

// handleTopology returns namespace→pod topology.
func (s *Server) handleTopology(c *fiber.Ctx) error {
	cacheKey := "topology"
	if cached, err := s.redis.Get(c.Context(), cacheKey); err == nil {
		c.Set("X-Cache", "HIT")
		return c.SendString(cached)
	}

	rows, err := s.ch.Query(c.Context(), `
		SELECT namespace, pod, node, count() AS cnt
		FROM kubepulse.events
		WHERE timestamp >= now() - INTERVAL 1 HOUR AND namespace != ''
		GROUP BY namespace, pod, node
		ORDER BY cnt DESC
		LIMIT 500
	`)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	defer rows.Close()

	var items []fiber.Map
	for rows.Next() {
		var ns, pod, node string
		var cnt uint64
		if err := rows.Scan(&ns, &pod, &node, &cnt); err != nil {
			continue
		}
		items = append(items, fiber.Map{
			"namespace": ns, "pod": pod, "node": node, "count": cnt,
		})
	}

	result, _ := json.Marshal(fiber.Map{"topology": items})
	s.redis.Set(c.Context(), cacheKey, string(result), constants.RedisCacheTTL)
	c.Set("X-Cache", "MISS")
	return c.Send(result)
}

// handleWS streams live events via WebSocket (backed by Redis pub/sub).
func (s *Server) handleWS(c *websocket.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := s.redis.Subscribe(ctx, constants.RedisPubSubChannel)
	defer sub.Close()

	ch := sub.Channel()
	for msg := range ch {
		if err := c.WriteMessage(websocket.TextMessage, []byte(msg.Payload)); err != nil {
			break
		}
	}
}

// sanitizeInterval prevents injection in interval strings.
func sanitizeInterval(s string) string {
	// Allow only digits + h/m/d
	for _, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if c == 'h' || c == 'm' || c == 'd' {
			continue
		}
		return "1 HOUR"
	}
	// Convert shorthand: "1h" → "1 HOUR"
	if len(s) >= 2 {
		num := s[:len(s)-1]
		if _, err := strconv.Atoi(num); err == nil {
			switch s[len(s)-1] {
			case 'h':
				return num + " HOUR"
			case 'm':
				return num + " MINUTE"
			case 'd':
				return fmt.Sprintf("%d HOUR", mustAtoi(num)*24)
			}
		}
	}
	return "1 HOUR"
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
