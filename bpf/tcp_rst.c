// go:build ignore

// KubePulse TCP RST Tracer
// Hooks tracepoint/tcp/tcp_send_reset to detect connection resets.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define RINGBUF_SIZE (1 * 1024 * 1024)

struct rst_event {
  __u32 pid;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u16 family;
  __u16 _pad;
  __u32 state;
  __u32 _pad2;
  __u64 timestamp;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} rst_events SEC(".maps");

SEC("tracepoint/tcp/tcp_send_reset")
int tracepoint_tcp_send_reset(struct trace_event_raw_tcp_event_sk_skb *ctx) {
  struct rst_event *event;

  event = bpf_ringbuf_reserve(&rst_events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->timestamp = bpf_ktime_get_ns();
  event->sport = ctx->sport;
  event->dport = ctx->dport;
  event->family = ctx->family;
  event->state = ctx->state;
  bpf_probe_read_kernel(&event->saddr, 4, ctx->saddr);
  bpf_probe_read_kernel(&event->daddr, 4, ctx->daddr);
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
