// Package config provides YAML-based configuration for KubePulse.
// Supports validation, defaults, and structured module/exporter config.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for KubePulse.
type Config struct {
	Agent       AgentConfig              `yaml:"agent"`
	Modules     map[string]*ModuleConfig `yaml:"modules"`
	Exporters   ExportersConfig          `yaml:"exporters"`
	Performance PerformanceConfig        `yaml:"performance"`
}

// AgentConfig holds global agent settings.
type AgentConfig struct {
	MetricsAddr string `yaml:"metrics_addr"`
	NodeName    string `yaml:"node_name"`
	LogLevel    string `yaml:"log_level"`
}

// ModuleConfig holds per-module settings.
type ModuleConfig struct {
	Enabled        bool    `yaml:"enabled"`
	RingBufferSize int     `yaml:"ring_buffer_size"`
	SamplingRate   float64 `yaml:"sampling_rate"`
}

// ExportersConfig holds exporter settings.
type ExportersConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"`
	OTLP       OTLPConfig       `yaml:"otlp"`
}

// PrometheusConfig holds Prometheus exporter settings.
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// OTLPConfig holds OpenTelemetry exporter settings (future).
type OTLPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// PerformanceConfig holds performance tuning parameters.
type PerformanceConfig struct {
	EventBusBuffer int `yaml:"event_bus_buffer"`
	WorkerPoolSize int `yaml:"worker_pool_size"`
}

// Default returns a Config with sensible production defaults.
func Default() *Config {
	modules := map[string]*ModuleConfig{
		"tcp":        {Enabled: true, RingBufferSize: 262144, SamplingRate: 1.0},
		"dns":        {Enabled: true, RingBufferSize: 262144, SamplingRate: 1.0},
		"retransmit": {Enabled: true, RingBufferSize: 131072, SamplingRate: 1.0},
		"rst":        {Enabled: true, RingBufferSize: 131072, SamplingRate: 1.0},
		"oom":        {Enabled: true, RingBufferSize: 65536, SamplingRate: 1.0},
		"exec":       {Enabled: true, RingBufferSize: 131072, SamplingRate: 1.0},
		"fileio":     {Enabled: true, RingBufferSize: 262144, SamplingRate: 1.0},
		"drop":       {Enabled: true, RingBufferSize: 131072, SamplingRate: 1.0},
	}

	hostname, _ := os.Hostname()

	return &Config{
		Agent: AgentConfig{
			MetricsAddr: ":9090",
			NodeName:    hostname,
			LogLevel:    "info",
		},
		Modules: modules,
		Exporters: ExportersConfig{
			Prometheus: PrometheusConfig{Enabled: true, Addr: ":9090"},
			OTLP:       OTLPConfig{Enabled: false},
		},
		Performance: PerformanceConfig{
			EventBusBuffer: 4096,
			WorkerPoolSize: 4,
		},
	}
}

// Load reads a YAML config file and merges with defaults.
// If the file doesn't exist, returns defaults.
// Environment variables override: KUBEPULSE_METRICS_ADDR, KUBEPULSE_NODE_NAME.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use defaults + env overrides
			cfg.applyEnvOverrides()
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.applyEnvOverrides()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// applyEnvOverrides allows environment variables to override config values.
func (c *Config) applyEnvOverrides() {
	if addr := os.Getenv("KUBEPULSE_METRICS_ADDR"); addr != "" {
		c.Agent.MetricsAddr = addr
		c.Exporters.Prometheus.Addr = addr
	}
	if node := os.Getenv("KUBEPULSE_NODE_NAME"); node != "" {
		c.Agent.NodeName = node
	}
	if level := os.Getenv("KUBEPULSE_LOG_LEVEL"); level != "" {
		c.Agent.LogLevel = level
	}
}

// Validate checks the config for logical errors.
func (c *Config) Validate() error {
	var errs []string

	if c.Agent.MetricsAddr == "" {
		errs = append(errs, "agent.metrics_addr is required")
	}
	if c.Performance.EventBusBuffer < 64 {
		errs = append(errs, "performance.event_bus_buffer must be >= 64")
	}
	if c.Performance.WorkerPoolSize < 1 {
		errs = append(errs, "performance.worker_pool_size must be >= 1")
	}
	for name, mod := range c.Modules {
		if mod.SamplingRate < 0 || mod.SamplingRate > 1 {
			errs = append(errs, fmt.Sprintf("modules.%s.sampling_rate must be in [0, 1]", name))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ModuleEnabled returns true if the named module is enabled (or not configured, defaults to true).
func (c *Config) ModuleEnabled(name string) bool {
	mod, ok := c.Modules[name]
	if !ok {
		return true // default: enabled
	}
	return mod.Enabled
}

// ModuleConf returns the config for a specific module, or a default if not found.
func (c *Config) ModuleConf(name string) *ModuleConfig {
	mod, ok := c.Modules[name]
	if !ok {
		return &ModuleConfig{Enabled: true, RingBufferSize: 262144, SamplingRate: 1.0}
	}
	return mod
}
