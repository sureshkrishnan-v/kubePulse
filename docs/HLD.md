# KubePulse – High-Level Design (HLD)

> Version: 1.0.0 | Date: 2026-02-18 | Status: Approved

---

## 1. Problem Statement

Modern Kubernetes clusters run hundreds of microservices communicating over TCP and DNS. Operators lack **low-overhead, kernel-level visibility** into:

- **TCP connection latency** per pod/namespace (not just application-level metrics)
- **DNS query performance** and failure rates per workload
- **Network anomalies** that are invisible to application-layer instrumentation

Existing solutions (Istio sidecar, tcpdump, netstat) either impose significant overhead, require application changes, or lack Kubernetes context.

**KubePulse** solves this by attaching eBPF programs directly to the Linux kernel, capturing TCP and DNS events at nanosecond precision with <2% CPU overhead, enriching them with Kubernetes metadata, and exporting them as Prometheus metrics.

---

## 2. Goals

| Goal | Description |
|------|-------------|
| **Zero-instrumentation** | No application changes required |
| **Low overhead** | <2% CPU per node under 10k conn/sec |
| **Kubernetes-native** | Events labeled with pod, namespace, node |
| **Production-safe** | No kernel crashes, bounded memory, safe BPF |
| **Observable** | Prometheus metrics, Grafana-ready |
| **Deployable** | DaemonSet + Helm chart |

### Non-Goals
- Application-layer tracing (use OpenTelemetry for that)
- Full packet capture (use Wireshark/tcpdump for that)
- Windows or non-Linux kernels
- Kernel versions < 5.8 (no ring buffer support)

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Node                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     Linux Kernel                         │  │
│  │                                                          │  │
│  │  tcp_connect ──► [kprobe]──┐                             │  │
│  │  tcp_close   ──► [kprobe]──┤──► TCP Ring Buffer ──┐      │  │
│  │                            │                       │      │  │
│  │  udp_sendmsg ──► [kprobe]──┴──► DNS Ring Buffer ──┤      │  │
│  │                                                    │      │  │
│  │  BPF Maps:                                         │      │  │
│  │    conn_start  (LRU Hash, pid+sock → timestamp)    │      │  │
│  │    dns_start   (LRU Hash, pid+cookie → timestamp)  │      │  │
│  └────────────────────────────────────────────────────┼──────┘  │
│                                                       │         │
│  ┌────────────────────────────────────────────────────▼──────┐  │
│  │                    KubePulse Daemon (Go)                  │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │  │
│  │  │  BPF Loader │  │ Event Reader │  │ Metadata Cache │  │  │
│  │  │  (cilium/   │  │ (ring buffer │  │ (PID→container │  │  │
│  │  │   ebpf)     │  │  consumer)   │  │  →pod/ns)      │  │  │
│  │  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │  │
│  │         │                │                   │           │  │
│  │         └────────────────┼───────────────────┘           │  │
│  │                          │                               │  │
│  │                  ┌───────▼────────┐                      │  │
│  │                  │ Metrics Engine │                       │  │
│  │                  │ (Prometheus)   │                       │  │
│  │                  └───────┬────────┘                      │  │
│  │                          │                               │  │
│  │                  ┌───────▼────────┐                      │  │
│  │                  │ HTTP Exporter  │                       │  │
│  │                  │ :9090/metrics  │                       │  │
│  │                  └────────────────┘                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
   Prometheus ──► Grafana
```

---

## 4. Component Breakdown

### 4.1 eBPF Layer (`bpf/`)

Two eBPF programs compiled to BPF bytecode and loaded at runtime:

#### `tcp_tracer.c`
- **`kprobe/tcp_connect`**: Records `(pid, sock_ptr, ktime_ns)` into `conn_start` LRU hash map
- **`kretprobe/tcp_connect`**: Reads return value; on success, stores connection metadata
- **`kprobe/tcp_close`**: Looks up `conn_start`, computes `latency = now - start`, emits `TCPEvent` to ring buffer

**BPF Maps:**
| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `conn_start` | LRU_HASH | `{pid, sock_ptr}` | `u64 ktime_ns` | 65536 |
| `tcp_events` | RINGBUF | — | `TCPEvent` | 4MB |

#### `dns_tracer.c`
- **`kprobe/udp_sendmsg`**: Filters `dport == 53`, parses DNS query name from socket buffer, emits `DNSEvent` to ring buffer

**BPF Maps:**
| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `dns_events` | RINGBUF | — | `DNSEvent` | 2MB |

**Safety Guarantees:**
- All memory accesses use `bpf_probe_read_kernel` / `bpf_probe_read_user`
- DNS name parsing has explicit bounds checks (max 255 bytes per RFC 1035)
- LRU maps prevent unbounded growth
- No dynamic allocation in BPF programs

### 4.2 Go Loader (`internal/loader/`)

Uses `github.com/cilium/ebpf` to:
1. Load compiled BPF object (embedded via `//go:embed`)
2. Attach kprobes/kretprobes to kernel functions
3. Return handles to ring buffer readers and maps
4. Clean up on context cancellation

### 4.3 Probe Managers (`internal/probes/`)

- `tcp.go`: Reads `TCPEvent` structs from ring buffer, dispatches to metrics engine
- `dns.go`: Reads `DNSEvent` structs from ring buffer, dispatches to metrics engine
- `events.go`: Shared event struct definitions (mirroring BPF C structs)

### 4.4 Metadata Cache (`internal/metadata/`)

- `cgroup.go`: Reads `/proc/<pid>/cgroup` to extract container ID
- `k8s.go`: Uses `client-go` to watch Pod events and maintain `containerID → PodMeta` map
- `cache.go`: Thread-safe LRU cache with TTL eviction for PID → PodMeta lookups

**Resolution Flow:**
```
PID → /proc/<pid>/cgroup → container_id → k8s cache → {pod, namespace, node}
```

Cache TTL: 60s (configurable). Pod churn handled via Informer watch events.

### 4.5 Metrics Engine (`internal/metrics/`)

Prometheus metrics with low-cardinality labels:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kubepulse_tcp_latency_seconds` | Histogram | `namespace`, `pod`, `node` | TCP connection latency |
| `kubepulse_dns_queries_total` | Counter | `namespace`, `pod`, `domain`, `node` | DNS queries by domain |
| `kubepulse_dns_latency_seconds` | Histogram | `namespace`, `pod`, `node` | DNS resolution latency |
| `kubepulse_events_dropped_total` | Counter | `type` | Ring buffer overflow drops |

**Histogram Buckets (network-tuned):**
```
0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0
```
(100µs to 1s — covers LAN to WAN latencies)

**Label Safety:**
- `domain` label is truncated to registered domain (e.g., `google.com` not `www.api.google.com`) to prevent cardinality explosion
- No per-connection labels (no IP addresses, no ports)

### 4.6 HTTP Exporter (`internal/exporter/`)

- Serves `/metrics` on `:9090` (configurable)
- Uses `promhttp.Handler()`
- Includes `/healthz` and `/readyz` endpoints

---

## 5. Data Flow

### TCP Latency Flow
```
1. Process calls connect() syscall
2. Kernel executes tcp_connect()
3. kprobe fires → BPF stores {pid, sock} → ktime_ns in conn_start map
4. Connection completes or fails
5. Process closes socket → tcp_close() fires
6. BPF looks up conn_start, computes latency, emits TCPEvent to ring buffer
7. Go daemon reads TCPEvent from ring buffer
8. Metadata cache resolves PID → pod/namespace
9. Prometheus histogram updated with latency + labels
10. Prometheus scrapes /metrics
```

### DNS Query Flow
```
1. Process calls sendmsg() on UDP socket to port 53
2. kprobe fires → BPF parses DNS wire format from socket buffer
3. DNSEvent emitted to ring buffer with {pid, query_name, timestamp}
4. Go daemon reads DNSEvent
5. Metadata cache resolves PID → pod/namespace
6. Counter incremented, latency histogram updated
7. Prometheus scrapes /metrics
```

---

## 6. Deployment Model

### DaemonSet Requirements
```yaml
hostPID: true          # Required: PID namespace for /proc/<pid>/cgroup
privileged: true       # Required: BPF program loading
hostNetwork: false     # Not required
volumes:
  - /sys/fs/bpf        # BPF filesystem
  - /proc              # Process metadata
```

### Resource Limits (per node)
```yaml
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 200m
    memory: 256Mi
```

### Helm Chart
- Configurable via `values.yaml`
- ServiceMonitor for Prometheus Operator
- RBAC for Kubernetes API access (Pod watch)
- PodSecurityPolicy / SecurityContextConstraints

---

## 7. Performance Design

| Concern | Solution |
|---------|----------|
| BPF map growth | LRU maps with bounded max entries |
| Ring buffer overflow | Overflow counter + backpressure in Go |
| Metadata lookup cost | In-memory LRU cache, O(1) lookup |
| Prometheus cardinality | Domain truncation, no per-IP labels |
| CPU overhead | Ring buffer (not perf_event_array), batch reads |
| Memory leaks | Explicit cleanup in kprobe detach, context cancel |

**Target:** <2% CPU overhead at 10k TCP connections/sec on a 4-core node.

---

## 8. Security Design

| Risk | Mitigation |
|------|------------|
| Kernel crash from bad BPF | BPF verifier enforces safety; no unbounded loops |
| DNS parse overflow | Explicit `len < 255` bounds check before every read |
| Privilege escalation | Minimal capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` |
| High cardinality DoS | Domain label truncation, max label value length |
| Map exhaustion | LRU eviction, bounded sizes |

---

## 9. Kernel Version Requirements

| Feature | Min Kernel |
|---------|-----------|
| kprobe BPF | 4.1 |
| BPF ring buffer | 5.8 |
| BTF (CO-RE) | 5.4 |

**Minimum supported: Linux 5.8** (Ubuntu 20.10+, RHEL 8.3+, Debian 11+)

---

## 10. Project Structure

```
kubepulse/
├── cmd/
│   └── kubepulse/
│       └── main.go              # Entry point, config, signal handling
├── bpf/
│   ├── tcp_tracer.c             # TCP kprobe eBPF program
│   ├── dns_tracer.c             # DNS kprobe eBPF program
│   └── headers/                 # vmlinux.h, bpf_helpers.h
├── internal/
│   ├── loader/
│   │   └── loader.go            # BPF object loading + attachment
│   ├── probes/
│   │   ├── events.go            # Shared event structs (mirrors BPF C)
│   │   ├── tcp.go               # TCP ring buffer consumer
│   │   └── dns.go               # DNS ring buffer consumer
│   ├── metadata/
│   │   ├── cgroup.go            # PID → container ID via /proc
│   │   ├── k8s.go               # container ID → pod/namespace via k8s API
│   │   └── cache.go             # Thread-safe LRU metadata cache
│   ├── metrics/
│   │   └── metrics.go           # Prometheus metric definitions
│   └── exporter/
│       └── exporter.go          # HTTP server for /metrics
├── deployments/
│   └── daemonset.yaml           # Raw Kubernetes DaemonSet manifest
├── charts/
│   └── kubepulse/               # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── docs/
│   ├── HLD.md                   # This document
│   ├── LLD.md                   # Low-Level Design
│   └── architecture.md          # Architecture diagrams
├── Dockerfile                   # Multi-stage build
├── Makefile                     # Build, generate, test targets
├── go.mod
└── README.md
```

---

## 11. Phased Delivery

| Phase | Deliverable | Validation |
|-------|-------------|------------|
| 1 | TCP tracer → stdout | `curl` triggers events |
| 2 | DNS tracer → stdout | `dig` triggers events |
| 3 | Prometheus metrics | `curl :9090/metrics` |
| 4 | K8s metadata labels | Labels on metrics |
| 5 | Production hardening | Helm deploy, CI, tests |
