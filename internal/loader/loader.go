// Package loader handles loading and attaching eBPF programs.
// It manages all BPF object lifecycle: load, attach, and cleanup.
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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 retransmitTracer ../../bpf/tcp_retransmit.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 rstTracer ../../bpf/tcp_rst.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 oomTracer ../../bpf/oomkill.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 execTracer ../../bpf/exec_tracer.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 fileioTracer ../../bpf/fileio_tracer.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 dropTracer ../../bpf/drop_tracer.c -- -I../../bpf

// LoadedProbes holds references to all loaded BPF objects and ring buffer readers.
// Call Close() to detach all probes and release resources.
type LoadedProbes struct {
	// Objects (kept for Close())
	tcpObjs        tcpTracerObjects
	dnsObjs        dnsTracerObjects
	retransmitObjs retransmitTracerObjects
	rstObjs        rstTracerObjects
	oomObjs        oomTracerObjects
	execObjs       execTracerObjects
	fileioObjs     fileioTracerObjects
	dropObjs       dropTracerObjects

	// Attached links
	links []link.Link

	// Ring buffer readers (one per probe type)
	TCPReader        *ringbuf.Reader
	DNSReader        *ringbuf.Reader
	RetransmitReader *ringbuf.Reader
	RSTReader        *ringbuf.Reader
	OOMReader        *ringbuf.Reader
	ExecReader       *ringbuf.Reader
	FileIOReader     *ringbuf.Reader
	DropReader       *ringbuf.Reader
}

// Load loads all eBPF programs, attaches probes, and returns ring buffer readers.
// Must be run as root (sudo) — BPF program loading requires CAP_BPF + CAP_NET_ADMIN.
func Load() (*LoadedProbes, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("KubePulse requires root privileges. Run with: sudo ./bin/kubepulse")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: failed to remove memlock rlimit: %v", err)
	}

	lp := &LoadedProbes{}

	// --- TCP Tracer (kprobe) ---
	if err := loadTcpTracerObjects(&lp.tcpObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading tcp tracer objects: %w", err)
	}
	kpConnect, err := link.Kprobe("tcp_connect", lp.tcpObjs.KprobeTcpConnect, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching tcp_connect kprobe: %w", err)
	}
	lp.links = append(lp.links, kpConnect)

	kpClose, err := link.Kprobe("tcp_close", lp.tcpObjs.KprobeTcpClose, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching tcp_close kprobe: %w", err)
	}
	lp.links = append(lp.links, kpClose)

	lp.TCPReader, err = ringbuf.NewReader(lp.tcpObjs.TcpEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating tcp ring buffer reader: %w", err)
	}

	// --- DNS Tracer (kprobe) ---
	if err := loadDnsTracerObjects(&lp.dnsObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading dns tracer objects: %w", err)
	}
	kpUDP, err := link.Kprobe("udp_sendmsg", lp.dnsObjs.KprobeUdpSendmsg, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
	}
	lp.links = append(lp.links, kpUDP)

	lp.DNSReader, err = ringbuf.NewReader(lp.dnsObjs.DnsEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating dns ring buffer reader: %w", err)
	}

	// --- TCP Retransmit Tracer (tracepoint) ---
	if err := loadRetransmitTracerObjects(&lp.retransmitObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading retransmit tracer objects: %w", err)
	}
	tpRetransmit, err := link.Tracepoint("tcp", "tcp_retransmit_skb", lp.retransmitObjs.TracepointTcpRetransmit, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching tcp_retransmit_skb tracepoint: %w", err)
	}
	lp.links = append(lp.links, tpRetransmit)

	lp.RetransmitReader, err = ringbuf.NewReader(lp.retransmitObjs.RetransmitEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating retransmit ring buffer reader: %w", err)
	}

	// --- TCP RST Tracer (tracepoint) ---
	if err := loadRstTracerObjects(&lp.rstObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading rst tracer objects: %w", err)
	}
	tpRST, err := link.Tracepoint("tcp", "tcp_send_reset", lp.rstObjs.TracepointTcpSendReset, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching tcp_send_reset tracepoint: %w", err)
	}
	lp.links = append(lp.links, tpRST)

	lp.RSTReader, err = ringbuf.NewReader(lp.rstObjs.RstEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating rst ring buffer reader: %w", err)
	}

	// --- OOM Kill Tracer (tracepoint) ---
	if err := loadOomTracerObjects(&lp.oomObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading oom tracer objects: %w", err)
	}
	tpOOM, err := link.Tracepoint("oom", "mark_victim", lp.oomObjs.TracepointOomMarkVictim, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching oom/mark_victim tracepoint: %w", err)
	}
	lp.links = append(lp.links, tpOOM)

	lp.OOMReader, err = ringbuf.NewReader(lp.oomObjs.OomEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating oom ring buffer reader: %w", err)
	}

	// --- Exec Tracer (tracepoint) ---
	if err := loadExecTracerObjects(&lp.execObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading exec tracer objects: %w", err)
	}
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", lp.execObjs.TracepointSchedProcessExec, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching sched_process_exec tracepoint: %w", err)
	}
	lp.links = append(lp.links, tpExec)

	lp.ExecReader, err = ringbuf.NewReader(lp.execObjs.ExecEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating exec ring buffer reader: %w", err)
	}

	// --- File I/O Tracer (kprobe + kretprobe) ---
	if err := loadFileioTracerObjects(&lp.fileioObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading fileio tracer objects: %w", err)
	}
	kpVfsRead, err := link.Kprobe("vfs_read", lp.fileioObjs.KprobeVfsRead, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching vfs_read kprobe: %w", err)
	}
	lp.links = append(lp.links, kpVfsRead)

	krpVfsRead, err := link.Kretprobe("vfs_read", lp.fileioObjs.KretprobeVfsRead, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching vfs_read kretprobe: %w", err)
	}
	lp.links = append(lp.links, krpVfsRead)

	kpVfsWrite, err := link.Kprobe("vfs_write", lp.fileioObjs.KprobeVfsWrite, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching vfs_write kprobe: %w", err)
	}
	lp.links = append(lp.links, kpVfsWrite)

	krpVfsWrite, err := link.Kretprobe("vfs_write", lp.fileioObjs.KretprobeVfsWrite, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching vfs_write kretprobe: %w", err)
	}
	lp.links = append(lp.links, krpVfsWrite)

	lp.FileIOReader, err = ringbuf.NewReader(lp.fileioObjs.FileioEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating fileio ring buffer reader: %w", err)
	}

	// --- Packet Drop Tracer (tracepoint) ---
	if err := loadDropTracerObjects(&lp.dropObjs, nil); err != nil {
		lp.Close()
		return nil, fmt.Errorf("loading drop tracer objects: %w", err)
	}
	tpDrop, err := link.Tracepoint("skb", "kfree_skb", lp.dropObjs.TracepointKfreeSkb, nil)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("attaching kfree_skb tracepoint: %w", err)
	}
	lp.links = append(lp.links, tpDrop)

	lp.DropReader, err = ringbuf.NewReader(lp.dropObjs.DropEvents)
	if err != nil {
		lp.Close()
		return nil, fmt.Errorf("creating drop ring buffer reader: %w", err)
	}

	return lp, nil
}

// Close detaches all probes and releases resources.
func (lp *LoadedProbes) Close() {
	readers := []*ringbuf.Reader{
		lp.TCPReader, lp.DNSReader, lp.RetransmitReader, lp.RSTReader,
		lp.OOMReader, lp.ExecReader, lp.FileIOReader, lp.DropReader,
	}
	for _, r := range readers {
		if r != nil {
			r.Close()
		}
	}
	for _, l := range lp.links {
		l.Close()
	}
	lp.tcpObjs.Close()
	lp.dnsObjs.Close()
	lp.retransmitObjs.Close()
	lp.rstObjs.Close()
	lp.oomObjs.Close()
	lp.execObjs.Close()
	lp.fileioObjs.Close()
	lp.dropObjs.Close()
}
