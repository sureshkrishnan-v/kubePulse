// go:build ignore

// KubePulse DNS Tracer - eBPF Program
// Hooks udp_sendmsg to capture DNS queries (port 53).
// Parses DNS wire format query name with BPF-verifier-safe bounds checking.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum DNS query name length
#define MAX_DNS_NAME_LEN 128
// DNS header size
#define DNS_HEADER_SIZE 12
// Ring buffer size: 2MB
#define RINGBUF_SIZE (2 * 1024 * 1024)

// DNS event emitted to userspace
struct dns_event {
  __u32 pid;
  __u32 uid;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u64 latency_ns;
  __u64 timestamp;
  char qname[MAX_DNS_NAME_LEN];
  __u16 qname_len;
  char comm[16];
  __u8 _pad[6];
};

// Ring buffer for emitting DNS events to userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} dns_events SEC(".maps");

// parse_dns_name parses a DNS wire format name from a stack buffer into
// dot-separated human-readable form. All accesses are from the stack buffer,
// so no bpf_probe_read is needed. Uses bounded loops (kernel 5.3+).
static __always_inline int parse_dns_name(const unsigned char *payload,
                                          int payload_len, char *dst,
                                          int dst_len) {
  int src_pos = 0;
  int dst_pos = 0;

  // Outer loop: iterate over labels. Max 32 labels is generous for any domain.
  // No #pragma unroll — kernel 5.3+ supports bounded loops natively.
  for (int i = 0; i < 32; i++) {
    if (src_pos >= payload_len || src_pos >= dst_len)
      break;

    unsigned char llen = payload[src_pos];
    if (llen == 0)
      break;

    // Compression pointer or invalid
    if (llen >= 0xC0)
      break;

    // Cap label length — DNS max is 63, we cap at 32 for verifier
    int label_len = llen;
    if (label_len > 32)
      break;

    // Check source bounds
    if (src_pos + 1 + label_len > payload_len)
      break;

    // Add dot separator (not before first label)
    if (dst_pos > 0 && dst_pos < dst_len - 1) {
      dst[dst_pos] = '.';
      dst_pos++;
    }

    // Check destination bounds
    if (dst_pos + label_len >= dst_len - 1)
      break;

    // Copy label characters one by one (verifier can track bounds)
    for (int j = 0; j < 32; j++) {
      if (j >= label_len)
        break;
      if (dst_pos >= dst_len - 1)
        break;
      int src_idx = src_pos + 1 + j;
      if (src_idx >= payload_len || src_idx >= MAX_DNS_NAME_LEN)
        break;
      dst[dst_pos] = payload[src_idx];
      dst_pos++;
    }

    src_pos += 1 + label_len;
  }

  // Null-terminate
  if (dst_pos < dst_len)
    dst[dst_pos] = '\0';

  return dst_pos;
}

// kprobe/udp_sendmsg - Fires when a UDP message is sent.
// Filters for port 53 (DNS) and parses the query name.
SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

  if (!sk || !msg)
    return 0;

  // Check destination port - must be 53 (DNS)
  __u16 dport = 0;
  BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
  dport = bpf_ntohs(dport);
  if (dport != 53)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u64 uid_gid = bpf_get_current_uid_gid();

  // Get the iov_iter from msghdr to read DNS payload
  struct iov_iter iter;
  if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) != 0)
    return 0;

  const struct iovec *iov = NULL;
  if (bpf_probe_read_kernel(&iov, sizeof(iov), &iter.__iov) != 0)
    return 0;

  if (!iov)
    return 0;

  void *base = NULL;
  __kernel_size_t iov_len = 0;
  if (bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base) != 0)
    return 0;
  if (bpf_probe_read_kernel(&iov_len, sizeof(iov_len), &iov->iov_len) != 0)
    return 0;

  // Minimum DNS message: header (12) + 1 byte name + 4 bytes qtype/qclass
  if (!base || iov_len < DNS_HEADER_SIZE + 5 || iov_len > 512)
    return 0;

  // Read the raw DNS payload after the header into a stack buffer.
  unsigned char dns_payload[MAX_DNS_NAME_LEN];
  int payload_len = iov_len - DNS_HEADER_SIZE;
  if (payload_len <= 0)
    return 0;
  if (payload_len > MAX_DNS_NAME_LEN)
    payload_len = MAX_DNS_NAME_LEN;

  if (bpf_probe_read_user(dns_payload, payload_len & 0x7F,
                          (void *)base + DNS_HEADER_SIZE) != 0)
    return 0;

  // Reserve ring buffer space
  struct dns_event *event =
      bpf_ringbuf_reserve(&dns_events, sizeof(struct dns_event), 0);
  if (!event)
    return 0;

  // Fill basic event fields
  event->pid = pid;
  event->uid = uid_gid & 0xFFFFFFFF;
  event->timestamp = bpf_ktime_get_ns();
  event->latency_ns = 0;
  event->dport = dport;

  BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
  BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
  BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);

  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Parse DNS wire format from stack buffer
  int name_len = parse_dns_name(dns_payload, payload_len & 0x7F, event->qname,
                                MAX_DNS_NAME_LEN);
  event->qname_len = (__u16)name_len;

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
