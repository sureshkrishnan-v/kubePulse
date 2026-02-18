# KubePulse

[![CI](https://github.com/sureshkrishnan-v/kubePulse/actions/workflows/ci.yml/badge.svg)](https://github.com/sureshkrishnan-v/kubePulse/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/sureshkrishnan-v/kubePulse)](https://goreportcard.com/report/github.com/sureshkrishnan-v/kubePulse)

**eBPF-powered Kubernetes-aware TCP latency and DNS monitoring agent** — the heartbeat of your cluster.

KubePulse attaches eBPF kprobes directly to the Linux kernel to capture TCP connection latency and DNS queries with nanosecond precision, enriches events with Kubernetes pod metadata, and exports Prometheus metrics. Zero application changes required.

## Architecture

```
┌──────────────────────────────────────────────┐
│                Kubernetes Node               │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │            Linux Kernel                │  │
│  │  tcp_connect ──► kprobe ──┐            │  │
│  │  tcp_close   ──► kprobe ──┤► Ring Buf  │  │
│  │  udp_sendmsg ──► kprobe ──┘            │  │
│  └────────────────────┬───────────────────┘  │
│                       │                      │
│  ┌────────────────────▼───────────────────┐  │
│  │          KubePulse Daemon (Go)         │  │
│  │  BPF Loader → Event Reader → Metrics  │  │
│  │  Metadata Cache (PID → Pod/Namespace) │  │
│  │  HTTP :9090/metrics                   │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
         │
    Prometheus ──► Grafana
```

## Features

- **TCP Latency Monitoring** — Measures connect-to-close latency per connection
- **DNS Query Monitoring** — Captures DNS queries (UDP port 53) with domain parsing
- **Kubernetes Awareness** — Maps PID → container → pod/namespace automatically
- **Prometheus Metrics** — Histograms and counters with low-cardinality labels
- **Production Safe** — LRU maps, bounded ring buffers, no kernel crashes
- **Low Overhead** — <2% CPU at 10k connections/sec

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kubepulse_tcp_latency_seconds` | Histogram | `namespace`, `pod`, `node` | TCP connection latency |
| `kubepulse_dns_queries_total` | Counter | `namespace`, `pod`, `domain`, `node` | DNS queries |
| `kubepulse_dns_latency_seconds` | Histogram | `namespace`, `pod`, `node` | DNS latency |
| `kubepulse_events_dropped_total` | Counter | `type` | Ring buffer overflow |
| `kubepulse_events_total` | Counter | `type` | Total events processed |

## Requirements

- Linux kernel ≥ 5.8 (BPF ring buffer support)
- `clang`, `llvm` (build time only)
- Go ≥ 1.22

## Quick Start

### Build from source

```bash
# Install BPF build dependencies (Ubuntu/Debian)
sudo apt install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r)

# Build
make generate  # Compile BPF C → Go bindings
make build     # Build the kubepulse binary

# Run (requires root for BPF program loading)
sudo ./bin/kubepulse
```

### Test with traffic

```bash
# Terminal 1: Run KubePulse
sudo ./bin/kubepulse

# Terminal 2: Generate TCP traffic
curl https://google.com
curl https://github.com

# Terminal 2: Generate DNS traffic
dig google.com
nslookup kubernetes.io

# Terminal 2: Check Prometheus metrics
curl http://localhost:9090/metrics | grep kubepulse
```

### Expected output

```
{"level":"info","ts":"...","msg":"tcp_event","pid":12345,"comm":"curl","src":"10.0.0.1:54321","dst":"142.250.190.78:443","latency_ms":12.4,"latency_human":"12.40ms"}
{"level":"info","ts":"...","msg":"dns_event","pid":9876,"comm":"dig","query":"google.com","domain":"google.com","dns_server":"127.0.0.53:53"}
```

### Deploy to Kubernetes

**Using Helm:**
```bash
helm install kubepulse charts/kubepulse -n kubepulse --create-namespace
```

**Using raw manifest:**
```bash
kubectl apply -f deployments/daemonset.yaml
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `KUBEPULSE_METRICS_ADDR` | `:9090` | Prometheus metrics listen address |
| `KUBEPULSE_NODE_NAME` | hostname | Node name for metric labels |
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig (outside cluster) |

## Project Structure

```
kubepulse/
├── cmd/kubepulse/         # Application entry point
├── bpf/                   # eBPF C programs
│   ├── tcp_tracer.c       # TCP kprobe program
│   ├── dns_tracer.c       # DNS kprobe program
│   └── headers/           # vmlinux.h
├── internal/
│   ├── loader/            # BPF program loading
│   ├── probes/            # Ring buffer consumers
│   ├── metadata/          # PID → K8s metadata
│   ├── metrics/           # Prometheus metrics
│   └── exporter/          # HTTP server
├── deployments/           # Raw K8s manifests
├── charts/kubepulse/      # Helm chart
├── docs/                  # HLD, LLD
├── Dockerfile             # Multi-stage build
└── Makefile
```

## Documentation

- [High-Level Design (HLD)](docs/HLD.md)
- [Low-Level Design (LLD)](docs/LLD.md)

## Performance

- **CPU overhead**: <2% per node under moderate load (10k conn/sec)
- **Memory**: ~64MB RSS typical, 256MB limit
- **BPF map memory**: ~2.5MB (LRU hash) + 6MB (ring buffers)
- **Latency resolution**: Nanosecond precision (ktime_get_ns)

### Benchmarking

```bash
# Run Go benchmarks
go test -bench=. -benchmem ./internal/...

# Measure CPU overhead under load
sudo ./bin/kubepulse &
# Generate 10k connections and compare CPU usage with/without KubePulse
```

## Security

- All BPF memory accesses use `bpf_probe_read_kernel` / `bpf_probe_read_user`
- DNS name parsing has explicit bounds checks (max 255 bytes per RFC 1035)
- LRU maps prevent unbounded memory growth
- Minimal capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`
- No per-connection labels (prevents cardinality explosion)
- Distroless runtime container image

## License

MIT License — see [LICENSE](LICENSE) for details.