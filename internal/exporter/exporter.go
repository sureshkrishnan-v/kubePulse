// Package exporter provides an HTTP server for Prometheus metrics and health endpoints.
package exporter

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server is an HTTP server that exposes Prometheus metrics and health endpoints.
type Server struct {
	httpServer *http.Server
	logger     *zap.Logger
	ready      atomic.Bool
}

// New creates a new exporter server listening on the given address.
// Example: New(":9090", logger)
func New(addr string, logger *zap.Logger) *Server {
	s := &Server{
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// SetReady marks the server as ready to serve traffic.
// Call this after all probes are attached.
func (s *Server) SetReady() {
	s.ready.Store(true)
}

// Run starts the HTTP server. It blocks until the context is cancelled
// or the server encounters a fatal error.
func (s *Server) Run(ctx context.Context) error {
	s.logger.Info("Starting metrics exporter",
		zap.String("addr", s.httpServer.Addr),
		zap.String("metrics_path", "/metrics"))

	// Handle graceful shutdown
	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down metrics exporter...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("metrics exporter shutdown error", zap.Error(err))
		}
	}()

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics exporter failed: %w", err)
	}

	return nil
}

// handleHealthz is a liveness probe endpoint.
// Always returns 200 OK if the process is alive.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

// handleReadyz is a readiness probe endpoint.
// Returns 200 OK only after SetReady() is called (i.e., after probes are attached).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready\n"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready\n"))
	}
}
