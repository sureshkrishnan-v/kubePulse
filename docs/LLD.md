# KubePulse – Low-Level Design (LLD)

> Version: 1.0.0 | Date: 2026-02-18

---

## 1. BPF Map Layouts

### 1.1 Connection Tracking Map (`conn_start`)
```
Type:        BPF_MAP_TYPE_LRU_HASH
Max Entries: 65536
Key Size:    16 bytes (conn_key)
Value Size:  24 bytes (conn_val)
Memory:      ~2.5 MB maximum
```

**Key (`conn_key`):**
| Field    | Type     | Offset | Description |
|----------|----------|--------|-------------|
| pid      | `__u32`  | 0      | Process ID |
| _pad     | `[4]byte`| 4      | Alignment padding |
| sock_ptr | `__u64`  | 8      | Socket pointer (address) |

**Value (`conn_val`):**
| Field    | Type    | Offset | Description |
|----------|---------|--------|-------------|
| start_ns | `__u64` | 0      | ktime_get_ns() at connect |
| saddr    | `__u32` | 8      | Source IPv4 |
| daddr    | `__u32` | 12     | Destination IPv4 |
| sport    | `__u16` | 16     | Source port |
| dport    | `__u16` | 18     | Destination port |
| uid      | `__u32` | 20     | User ID |

### 1.2 TCP Event Ring Buffer (`tcp_events`)
```
Type:        BPF_MAP_TYPE_RINGBUF
Max Entries: 4MB (4194304 bytes)
```

### 1.3 DNS Event Ring Buffer (`dns_events`)
```
Type:        BPF_MAP_TYPE_RINGBUF
Max Entries: 2MB (2097152 bytes)
```

---

## 2. Event Structs (Wire Format)

### 2.1 TCPEvent (56 bytes)
| Field       | Type     | Offset | Size | Description |
|-------------|----------|--------|------|-------------|
| pid         | `u32`    | 0      | 4    | Process ID |
| uid         | `u32`    | 4      | 4    | User ID |
| saddr       | `u32`    | 8      | 4    | Source IPv4 |
| daddr       | `u32`    | 12     | 4    | Dest IPv4 |
| sport       | `u16`    | 16     | 2    | Source port |
| dport       | `u16`    | 18     | 2    | Dest port |
| latency_ns  | `u64`    | 24     | 8    | Latency (ns) |
| timestamp   | `u64`    | 32     | 8    | Kernel timestamp |
| comm        | `[16]u8` | 40     | 16   | Process name |

### 2.2 DNSEvent (320 bytes)
| Field       | Type      | Offset | Size | Description |
|-------------|-----------|--------|------|-------------|
| pid         | `u32`     | 0      | 4    | Process ID |
| uid         | `u32`     | 4      | 4    | User ID |
| saddr       | `u32`     | 8      | 4    | Source IPv4 |
| daddr       | `u32`     | 12     | 4    | DNS server IPv4 |
| sport       | `u16`     | 16     | 2    | Source port |
| dport       | `u16`     | 18     | 2    | Dest port (53) |
| latency_ns  | `u64`     | 24     | 8    | Reserved |
| timestamp   | `u64`     | 32     | 8    | Kernel timestamp |
| qname       | `[256]u8` | 40     | 256  | DNS query name |
| qname_len   | `u16`     | 296    | 2    | Query name length |
| comm        | `[16]u8`  | 298    | 16   | Process name |
| _pad        | `[6]u8`   | 314    | 6    | Alignment padding |

---

## 3. Concurrency Model

```
                    ┌──────────────────────────────────────┐
                    │            main goroutine            │
                    │  (signal handling, lifecycle mgmt)   │
                    └──┬──────────┬──────────┬──────────┬──┘
                       │          │          │          │
                ┌──────▼──┐ ┌────▼────┐ ┌───▼───┐ ┌───▼────────┐
                │TCP Probe│ │DNS Probe│ │HTTP   │ │K8s Watcher │
                │goroutine│ │goroutine│ │Server │ │goroutine   │
                │         │ │         │ │(net/  │ │(Informer)  │
                │ringbuf  │ │ringbuf  │ │http)  │ │            │
                │.Read()  │ │.Read()  │ │       │ │Watch Pods  │
                └────┬────┘ └────┬────┘ └───┬───┘ └──────┬─────┘
                     │           │          │            │
                     ▼           ▼          │            ▼
              handleTCPEvent  handleDNSEvent│     UpdatePod/
                     │           │          │     DeletePod
                     ├───────────┘          │         │
                     ▼                      │         ▼
              ┌────────────┐               │  ┌──────────┐
              │ Metadata   │               │  │Container │
              │ Cache      │◄──────────────┼──│Index     │
              │ (sync.RW   │               │  │(sync.RW  │
              │  Mutex)    │               │  │ Mutex)   │
              └─────┬──────┘               │  └──────────┘
                    │                      │
                    ▼                      │
              ┌────────────┐               │
              │ Prometheus │               │
              │ Metrics    │◄──────────────┘
              │ (atomic    │     HTTP GET /metrics
              │  counters) │
              └────────────┘
```

**Synchronization:**
- Ring buffer readers: Single-consumer per buffer (no contention)
- Metadata cache: `sync.RWMutex` for PID entries, separate `sync.RWMutex` for container index
- Prometheus: Atomic operations (lock-free)
- Context cancellation: All goroutines respect `ctx.Done()`

---

## 4. Metadata Resolution Flow

```
TCPEvent arrives (PID=1234)
    │
    ├── 1. Check PID cache (RLock)
    │   └── Cache hit + not expired → return PodMeta
    │
    ├── 2. Cache miss → read /proc/1234/cgroup
    │   └── Parse container ID (64-char hex) from cgroup path
    │
    ├── 3. Lookup container ID in containerIndex (RLock)
    │   └── containerIndex populated by K8s Informer
    │
    ├── 4. Found → cache PID → PodMeta (Lock)
    │   └── Return {namespace, pod, node}
    │
    └── 5. Not found → return empty labels
        └── Pod may not exist yet or PID is not containerized
```

**Performance characteristics:**
- Hot path (cache hit): O(1), single RLock
- Cold path (cache miss): 1 file read + 1 map lookup
- Peak throughput: 10k+ lookups/sec (benchmarked)

---

## 5. Ring Buffer Overflow Handling

```
BPF side:
  bpf_ringbuf_reserve() returns NULL → event dropped silently
  (No crash, no kernel warning)

Go side:
  ringbuf.Reader.Read() returns records in order
  If ring buffer was full, records are simply not emitted
  
  kubepulse_events_dropped_total counter tracks awareness of pressure
```

---

## 6. DNS Parsing Safety

The DNS wire format parser in `dns_tracer.c` enforces:

1. **Bounds checking**: `src_pos < data_len && src_pos < 255`
2. **Label length validation**: `label_len < 0xC0` (no compression pointers)
3. **Destination buffer bounds**: `dst_pos + label_len < dst_len - 1`
4. **Maximum iterations**: `#pragma unroll` with limit of 128 labels
5. **User memory safety**: All reads via `bpf_probe_read_user()`
6. **Null termination**: Always null-terminates output buffer
