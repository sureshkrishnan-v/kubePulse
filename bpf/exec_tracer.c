// go:build ignore

// KubePulse Process Exec Tracer
// Hooks tracepoint/sched/sched_process_exec to monitor process executions.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define RINGBUF_SIZE (1 * 1024 * 1024)
#define MAX_FILENAME_LEN 128

struct exec_event {
  __u32 pid;
  __u32 uid;
  __u32 old_pid;
  __u32 _pad;
  __u64 timestamp;
  char comm[16];
  char filename[MAX_FILENAME_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} exec_events SEC(".maps");

// Uses vmlinux.h struct: trace_event_raw_sched_process_exec
SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(
    struct trace_event_raw_sched_process_exec *ctx) {
  struct exec_event *event;

  event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->pid = ctx->pid;
  event->old_pid = ctx->old_pid;
  event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  event->timestamp = bpf_ktime_get_ns();
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Read filename from __data_loc encoded field
  // __data_loc: lower 16 bits = offset, upper 16 bits = length
  unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
  unsigned short fname_len = (ctx->__data_loc_filename >> 16) & 0xFFFF;
  if (fname_len > MAX_FILENAME_LEN)
    fname_len = MAX_FILENAME_LEN;
  if (fname_len > 0) {
    bpf_probe_read_kernel(event->filename, fname_len & 0x7F,
                          (void *)ctx + fname_off);
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
