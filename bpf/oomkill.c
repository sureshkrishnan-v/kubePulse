// go:build ignore

// KubePulse OOMKill Detector
// Hooks tracepoint/oom/mark_victim to detect OOM kills.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define RINGBUF_SIZE (512 * 1024)

struct oom_event {
  __u32 pid; // Victim PID
  __u32 uid;
  __u64 total_vm;      // Total VM pages
  __u64 anon_rss;      // Anonymous RSS pages
  __u64 file_rss;      // File-backed RSS pages
  __u64 shmem_rss;     // Shared memory RSS pages
  __u64 pgtables;      // Page table pages
  __s16 oom_score_adj; // OOM score adjustment
  __u16 _pad;
  __u32 _pad2;
  __u64 timestamp;
  char comm[16]; // Victim process name
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} oom_events SEC(".maps");

// Use the vmlinux.h struct: trace_event_raw_mark_victim
SEC("tracepoint/oom/mark_victim")
int tracepoint_oom_mark_victim(struct trace_event_raw_mark_victim *ctx) {
  struct oom_event *event;

  event = bpf_ringbuf_reserve(&oom_events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->pid = ctx->pid;
  event->uid = ctx->uid;
  event->total_vm = ctx->total_vm;
  event->anon_rss = ctx->anon_rss;
  event->file_rss = ctx->file_rss;
  event->shmem_rss = ctx->shmem_rss;
  event->pgtables = ctx->pgtables;
  event->oom_score_adj = ctx->oom_score_adj;
  event->timestamp = bpf_ktime_get_ns();
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
