// Package loader handles loading eBPF programs and attaching kprobes.
package loader

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 tcpTracer ../../bpf/tcp_tracer.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 dnsTracer ../../bpf/dns_tracer.c -- -I../../bpf

// LoadedProbes holds references to the loaded BPF objects and attached probes.
// Call Close() to detach kprobes and release all resources.
type LoadedProbes struct {
	tcpObjs   tcpTracerObjects
	dnsObjs   dnsTracerObjects
	links     []link.Link
	TCPReader *ringbuf.Reader
	DNSReader *ringbuf.Reader
}

// Load loads the compiled eBPF TCP and DNS tracer programs, attaches kprobes,
// and returns a LoadedProbes handle with ring buffer readers.
// Must be run as root (sudo) — BPF program loading requires CAP_BPF + CAP_NET_ADMIN.
func Load() (*LoadedProbes, error) {
	// Check if running as root
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("KubePulse requires root privileges to load BPF programs. Run with: sudo ./bin/kubepulse")
	}

	// Best-effort: remove MEMLOCK rlimit for kernels < 5.11.
	// On newer kernels (5.11+) with cgroup-based memlock, this is a no-op.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: failed to remove memlock rlimit (may be fine on kernel 5.11+): %v", err)
	}

	lp := &LoadedProbes{}

	// --- TCP Tracer ---
	if err := loadTcpTracerObjects(&lp.tcpObjs, nil); err != nil {
		return nil, fmt.Errorf("loading tcp tracer objects: %w", err)
	}

	kpConnect, err := link.Kprobe("tcp_connect", lp.tcpObjs.KprobeTcpConnect, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching kprobe/tcp_connect: %w", err)
	}
	lp.links = append(lp.links, kpConnect)

	kpClose, err := link.Kprobe("tcp_close", lp.tcpObjs.KprobeTcpClose, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching kprobe/tcp_close: %w", err)
	}
	lp.links = append(lp.links, kpClose)

	tcpReader, err := ringbuf.NewReader(lp.tcpObjs.TcpEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating tcp ring buffer reader: %w", err)
	}
	lp.TCPReader = tcpReader

	// --- DNS Tracer ---
	if err := loadDnsTracerObjects(&lp.dnsObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading dns tracer objects: %w", err)
	}

	kpUDP, err := link.Kprobe("udp_sendmsg", lp.dnsObjs.KprobeUdpSendmsg, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching kprobe/udp_sendmsg: %w", err)
	}
	lp.links = append(lp.links, kpUDP)

	dnsReader, err := ringbuf.NewReader(lp.dnsObjs.DnsEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating dns ring buffer reader: %w", err)
	}
	lp.DNSReader = dnsReader

	return lp, nil
}

// Close detaches all kprobes, closes ring buffer readers, and frees BPF resources.
func (lp *LoadedProbes) Close() {
	if lp.TCPReader != nil {
		lp.TCPReader.Close()
	}
	if lp.DNSReader != nil {
		lp.DNSReader.Close()
	}
	for _, l := range lp.links {
		l.Close()
	}
	lp.tcpObjs.Close()
	lp.dnsObjs.Close()
}
