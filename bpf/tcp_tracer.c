//go:build ignore

// KubePulse TCP Tracer - eBPF Program
// Attaches kprobes to tcp_connect and tcp_close to measure per-connection latency.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Maximum tracked connections in LRU map
#define MAX_CONNECTIONS 65536

// Ring buffer size: 4MB
#define RINGBUF_SIZE (4 * 1024 * 1024)

// TCP event emitted to userspace
struct tcp_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;     // Source IPv4 address
    __u32 daddr;     // Destination IPv4 address
    __u16 sport;     // Source port
    __u16 dport;     // Destination port
    __u64 latency_ns;
    __u64 timestamp;
    char comm[16];   // Process name
};

// Key for the connection tracking map
struct conn_key {
    __u32 pid;
    __u64 sock_ptr;  // struct sock pointer as u64
};

// Value stored in the connection tracking map
struct conn_val {
    __u64 start_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 uid;
};

// LRU hash map: tracks start time of connections
// LRU ensures we never exceed MAX_CONNECTIONS and stale entries are evicted.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} conn_start SEC(".maps");

// Ring buffer for emitting TCP events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} tcp_events SEC(".maps");

// kprobe/tcp_connect - Fires when a TCP connection is initiated.
// Records the start timestamp, source/dest addresses and ports.
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;

    struct conn_key key = {
        .pid = pid,
        .sock_ptr = (__u64)sk,
    };

    struct conn_val val = {
        .start_ns = bpf_ktime_get_ns(),
        .uid = uid,
    };

    // Read socket addresses using CO-RE
    BPF_CORE_READ_INTO(&val.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&val.daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&val.dport, sk, __sk_common.skc_dport);
    val.dport = bpf_ntohs(val.dport);

    // Read source port
    BPF_CORE_READ_INTO(&val.sport, sk, __sk_common.skc_num);

    bpf_map_update_elem(&conn_start, &key, &val, BPF_ANY);
    return 0;
}

// kprobe/tcp_close - Fires when a TCP connection is closed.
// Looks up the start time, computes latency, and emits an event.
SEC("kprobe/tcp_close")
int kprobe_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct conn_key key = {
        .pid = pid,
        .sock_ptr = (__u64)sk,
    };

    // Look up connection start data
    struct conn_val *val = bpf_map_lookup_elem(&conn_start, &key);
    if (!val) {
        // Connection wasn't tracked (e.g., started before our program loaded)
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_ns = now - val->start_ns;

    // Reserve space in ring buffer
    struct tcp_event *event = bpf_ringbuf_reserve(&tcp_events, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full - event is dropped.
        // Userspace tracks this via the ring buffer overflow callback.
        bpf_map_delete_elem(&conn_start, &key);
        return 0;
    }

    // Fill event
    event->pid = pid;
    event->uid = val->uid;
    event->saddr = val->saddr;
    event->daddr = val->daddr;
    event->sport = val->sport;
    event->dport = val->dport;
    event->latency_ns = latency_ns;
    event->timestamp = now;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    // Clean up the connection tracking entry
    bpf_map_delete_elem(&conn_start, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
