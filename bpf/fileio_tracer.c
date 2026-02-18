// go:build ignore

// KubePulse File I/O Latency Tracer
// Hooks kprobe/vfs_read, kretprobe/vfs_read, kprobe/vfs_write,
// kretprobe/vfs_write to measure file I/O latency.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (2 * 1024 * 1024)
#define MAX_ENTRIES 8192

// Track in-flight I/O operations
struct io_key {
  __u32 pid;
  __u32 tid;
};

struct io_val {
  __u64 start_ns;
  __u8 op; // 0=read, 1=write
  __u8 _pad[7];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct io_key);
  __type(value, struct io_val);
} io_start SEC(".maps");

struct fileio_event {
  __u32 pid;
  __u32 uid;
  __u64 latency_ns;
  __u64 bytes;
  __u64 timestamp;
  __u8 op; // 0=read, 1=write
  __u8 _pad[7];
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} fileio_events SEC(".maps");

static __always_inline int io_entry(__u8 op) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct io_key key = {
      .pid = pid_tgid >> 32,
      .tid = (__u32)pid_tgid,
  };
  struct io_val val = {
      .start_ns = bpf_ktime_get_ns(),
      .op = op,
  };
  bpf_map_update_elem(&io_start, &key, &val, BPF_ANY);
  return 0;
}

static __always_inline int io_exit(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct io_key key = {
      .pid = pid_tgid >> 32,
      .tid = (__u32)pid_tgid,
  };

  struct io_val *val = bpf_map_lookup_elem(&io_start, &key);
  if (!val)
    return 0;

  __u64 latency = bpf_ktime_get_ns() - val->start_ns;
  __u8 op = val->op;
  bpf_map_delete_elem(&io_start, &key);

  // Filter out very fast I/O (< 1ms) to reduce noise
  if (latency < 1000000)
    return 0;

  struct fileio_event *event =
      bpf_ringbuf_reserve(&fileio_events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->pid = key.pid;
  event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  event->latency_ns = latency;
  event->bytes = PT_REGS_RC(ctx);
  event->timestamp = bpf_ktime_get_ns();
  event->op = op;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx) { return io_entry(0); }

SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx) { return io_exit(ctx); }

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) { return io_entry(1); }

SEC("kretprobe/vfs_write")
int kretprobe_vfs_write(struct pt_regs *ctx) { return io_exit(ctx); }

char LICENSE[] SEC("license") = "GPL";
