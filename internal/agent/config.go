package agent

import "os"

// Config holds all agent configuration, loaded from environment variables.
type Config struct {
	// MetricsAddr is the listen address for the Prometheus HTTP exporter.
	MetricsAddr string

	// NodeName is the Kubernetes node name, used as a Prometheus label.
	NodeName string
}

// LoadConfig reads configuration from environment variables with sensible defaults.
func LoadConfig() *Config {
	cfg := &Config{
		MetricsAddr: ":9090",
	}

	if addr := os.Getenv("KUBEPULSE_METRICS_ADDR"); addr != "" {
		cfg.MetricsAddr = addr
	}

	if node := os.Getenv("KUBEPULSE_NODE_NAME"); node != "" {
		cfg.NodeName = node
	} else {
		cfg.NodeName, _ = os.Hostname()
	}

	return cfg
}
