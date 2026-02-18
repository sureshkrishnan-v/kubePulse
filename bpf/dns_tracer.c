// go:build ignore

// KubePulse DNS Tracer - eBPF Program
// Hooks udp_sendmsg to capture DNS queries (port 53).
// Parses DNS wire format query name with explicit bounds checking.

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum DNS query name length per RFC 1035
#define MAX_DNS_NAME_LEN 256
// DNS header size
#define DNS_HEADER_SIZE 12
// Ring buffer size: 2MB
#define RINGBUF_SIZE (2 * 1024 * 1024)
// Max entries for DNS start time tracking
#define MAX_DNS_ENTRIES 32768

// DNS event emitted to userspace
struct dns_event {
  __u32 pid;
  __u32 uid;
  __u32 saddr;      // Source IPv4 address
  __u32 daddr;      // Destination IPv4 address (DNS server)
  __u16 sport;      // Source port
  __u16 dport;      // Destination port (should be 53)
  __u64 latency_ns; // Not used in the sendmsg-only path; reserved for future
                    // recv hook
  __u64 timestamp;  // Kernel timestamp
  char qname[MAX_DNS_NAME_LEN]; // DNS query name (dot-separated,
                                // null-terminated)
  __u16 qname_len;              // Length of query name string
  char comm[16];                // Process command name
  __u8 _pad[6];                 // Padding for 8-byte alignment
};

// Ring buffer for emitting DNS events to userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} dns_events SEC(".maps");

// parse_dns_name: Safely parse DNS wire format name into dot-separated string.
// DNS wire format: [3]www[6]google[3]com[0]
// Output: "www.google.com"
//
// Safety: All reads use bpf_probe_read_user with explicit bounds.
// Returns the number of bytes written to dst, or 0 on failure.
static __always_inline int parse_dns_name(const unsigned char *dns_data,
                                          int data_len, char *dst,
                                          int dst_len) {
  int src_pos = 0;
  int dst_pos = 0;
  int label_len;

// DNS name consists of labels: [len][chars...][len][chars...]...[0]
// Maximum iterations to prevent BPF verifier from complaining about unbounded
// loops
#pragma unroll
  for (int i = 0; i < 128; i++) {
    if (src_pos >= data_len || src_pos >= 255) {
      break;
    }

    // Read label length
    unsigned char llen = 0;
    if (bpf_probe_read_user(&llen, 1, dns_data + src_pos) != 0) {
      break;
    }

    label_len = llen;

    // End of name
    if (label_len == 0) {
      break;
    }

    // Compression pointer (starts with 0xC0) - we don't follow these
    if (label_len >= 0xC0) {
      break;
    }

    // Bounds check: label_len must fit in remaining source data
    if (src_pos + 1 + label_len > data_len || src_pos + 1 + label_len > 255) {
      break;
    }

    // Add dot separator (not before first label)
    if (dst_pos > 0) {
      if (dst_pos >= dst_len - 1) {
        break;
      }
      dst[dst_pos] = '.';
      dst_pos++;
    }

    // Bounds check: ensure we have room in destination
    if (dst_pos + label_len >= dst_len - 1) {
      break;
    }

    // Read label characters
    if (bpf_probe_read_user(dst + dst_pos, label_len, dns_data + src_pos + 1) !=
        0) {
      break;
    }

    dst_pos += label_len;
    src_pos += 1 + label_len;
  }

  // Null-terminate
  if (dst_pos < dst_len) {
    dst[dst_pos] = '\0';
  }

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
  // The DNS query starts after the 12-byte DNS header
  struct iov_iter iter;
  if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) != 0)
    return 0;

  // Read the first iovec
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

  // Minimum DNS message is header (12 bytes) + 1 byte name + 4 bytes (qtype +
  // qclass)
  if (!base || iov_len < DNS_HEADER_SIZE + 5 || iov_len > 512)
    return 0;

  // Reserve ring buffer space
  struct dns_event *event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
  if (!event)
    return 0;

  // Fill basic event fields
  event->pid = pid;
  event->uid = uid_gid & 0xFFFFFFFF;
  event->timestamp = bpf_ktime_get_ns();
  event->latency_ns = 0; // No response tracking in this hook
  event->dport = dport;

  BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
  BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
  BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);

  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Parse DNS query name from the payload (starts at offset 12, after DNS
  // header)
  int dns_data_len = iov_len - DNS_HEADER_SIZE;
  if (dns_data_len > 255)
    dns_data_len = 255;

  event->qname_len =
      parse_dns_name((const unsigned char *)base + DNS_HEADER_SIZE,
                     dns_data_len, event->qname, MAX_DNS_NAME_LEN);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
