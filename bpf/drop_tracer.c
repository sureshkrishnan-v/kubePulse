// go:build ignore

// KubePulse Packet Drop Tracer
// Hooks tracepoint/skb/kfree_skb to detect dropped packets with drop reasons.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define RINGBUF_SIZE (1 * 1024 * 1024)

struct drop_event {
  __u32 pid;
  __u32 drop_reason;
  __u16 protocol;
  __u16 _pad;
  __u32 _pad2;
  __u64 location; // Kernel function address where drop occurred
  __u64 timestamp;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} drop_events SEC(".maps");

// Tracepoint context for skb/kfree_skb
struct trace_event_raw_kfree_skb_ctx {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  void *skbaddr;
  void *location;
  unsigned short protocol;
  unsigned short _pad;
  unsigned int reason; // enum skb_drop_reason
};

SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb_ctx *ctx) {
  // Only trace drops with a specific reason (0 = SKB_CONSUMED, 1 =
  // SKB_DROP_REASON_NOT_SPECIFIED) We want drops with reason >= 2 (actual
  // drops, not normal consumption)
  if (ctx->reason < 2)
    return 0;

  struct drop_event *event =
      bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->drop_reason = ctx->reason;
  event->protocol = ctx->protocol;
  event->location = (__u64)ctx->location;
  event->timestamp = bpf_ktime_get_ns();
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
