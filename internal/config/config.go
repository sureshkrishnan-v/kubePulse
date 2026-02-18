// Package config provides YAML-based configuration for KubePulse.
// Supports validation, defaults, and structured module/exporter config.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
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

// NewModuleConfig creates a ModuleConfig with production defaults.
func NewModuleConfig(ringBufSize int) *ModuleConfig {
	return &ModuleConfig{
		Enabled:        true,
		RingBufferSize: ringBufSize,
		SamplingRate:   constants.DefaultSamplingRate,
	}
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
// All magic numbers are sourced from the constants package.
func Default() *Config {
	hostname, _ := os.Hostname()

	return &Config{
		Agent: AgentConfig{
			MetricsAddr: constants.DefaultMetricsAddr,
			NodeName:    hostname,
			LogLevel:    constants.DefaultLogLevel,
		},
		Modules: map[string]*ModuleConfig{
			constants.ModuleTCP:        NewModuleConfig(constants.RingBufLarge),
			constants.ModuleDNS:        NewModuleConfig(constants.RingBufLarge),
			constants.ModuleRetransmit: NewModuleConfig(constants.RingBufMedium),
			constants.ModuleRST:        NewModuleConfig(constants.RingBufMedium),
			constants.ModuleOOM:        NewModuleConfig(constants.RingBufSmall),
			constants.ModuleExec:       NewModuleConfig(constants.RingBufMedium),
			constants.ModuleFileIO:     NewModuleConfig(constants.RingBufLarge),
			constants.ModuleDrop:       NewModuleConfig(constants.RingBufMedium),
		},
		Exporters: ExportersConfig{
			Prometheus: PrometheusConfig{
				Enabled: true,
				Addr:    constants.DefaultMetricsAddr,
			},
			OTLP: OTLPConfig{Enabled: false},
		},
		Performance: PerformanceConfig{
			EventBusBuffer: constants.DefaultEventBusBuffer,
			WorkerPoolSize: constants.DefaultWorkerPoolSize,
		},
	}
}

// Load reads a YAML config file and merges with defaults.
// If the file doesn't exist, returns defaults.
// Environment variables override file settings.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
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
	if addr := os.Getenv(constants.EnvMetricsAddr); addr != "" {
		c.Agent.MetricsAddr = addr
		c.Exporters.Prometheus.Addr = addr
	}
	if node := os.Getenv(constants.EnvNodeName); node != "" {
		c.Agent.NodeName = node
	}
	if level := os.Getenv(constants.EnvLogLevel); level != "" {
		c.Agent.LogLevel = level
	}
}

// Validate checks the config for logical errors.
func (c *Config) Validate() error {
	var errs []string

	if c.Agent.MetricsAddr == "" {
		errs = append(errs, "agent.metrics_addr is required")
	}
	if c.Performance.EventBusBuffer < constants.MinEventBusBuffer {
		errs = append(errs, fmt.Sprintf(
			"performance.event_bus_buffer must be >= %d", constants.MinEventBusBuffer))
	}
	if c.Performance.WorkerPoolSize < constants.MinWorkerPoolSize {
		errs = append(errs, fmt.Sprintf(
			"performance.worker_pool_size must be >= %d", constants.MinWorkerPoolSize))
	}
	for name, mod := range c.Modules {
		if mod.SamplingRate < constants.MinSamplingRate || mod.SamplingRate > constants.MaxSamplingRate {
			errs = append(errs, fmt.Sprintf(
				"modules.%s.sampling_rate must be in [%.1f, %.1f]",
				name, constants.MinSamplingRate, constants.MaxSamplingRate))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ModuleEnabled returns whether the named module is enabled.
// Defaults to true if not configured.
func (c *Config) ModuleEnabled(name string) bool {
	mod, ok := c.Modules[name]
	if !ok {
		return true
	}
	return mod.Enabled
}

// ModuleConf returns the config for a module, or default if not found.
func (c *Config) ModuleConf(name string) *ModuleConfig {
	mod, ok := c.Modules[name]
	if !ok {
		return NewModuleConfig(constants.DefaultRingBufferSize)
	}
	return mod
}
