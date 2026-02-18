// Package probes provides event struct definitions that mirror the C structs
// defined in the BPF programs. These structs are read from ring buffers
// and MUST be byte-identical to their C counterparts.
package probes

import (
	"fmt"
	"unsafe"
)

// ---------- TCP Events ----------

// TCPEvent mirrors the tcp_event struct defined in bpf/tcp_tracer.c.
type TCPEvent struct {
	PID       uint32   // Process ID
	UID       uint32   // User ID
	SAddr     uint32   // Source IPv4 address
	DAddr     uint32   // Destination IPv4 address
	SPort     uint16   // Source port
	DPort     uint16   // Destination port
	LatencyNs uint64   // Connection latency in nanoseconds
	Timestamp uint64   // Kernel timestamp
	Comm      [16]byte // Process command name
}

// CommString returns the null-terminated process name as a Go string.
func (e *TCPEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// ---------- DNS Events ----------

// DNSEvent mirrors the dns_event struct defined in bpf/dns_tracer.c.
type DNSEvent struct {
	PID       uint32    // Process ID
	UID       uint32    // User ID
	SAddr     uint32    // Source IPv4 address
	DAddr     uint32    // Destination IPv4 address (DNS server)
	SPort     uint16    // Source port
	DPort     uint16    // Destination port (53)
	LatencyNs uint64    // DNS query latency in nanoseconds
	Timestamp uint64    // Kernel timestamp
	QName     [128]byte // DNS query name (dot-separated, null-terminated)
	QNameLen  uint16    // Length of the query name
	Comm      [16]byte  // Process command name
	_         [6]byte   // Padding for alignment
}

// CommString returns the process name.
func (e *DNSEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// QNameString returns the DNS query name.
func (e *DNSEvent) QNameString() string {
	l := int(e.QNameLen)
	if l > len(e.QName) {
		l = len(e.QName)
	}
	return string(e.QName[:l])
}

// ---------- TCP Retransmit Events ----------

// RetransmitEvent mirrors the retransmit_event struct in bpf/tcp_retransmit.c.
type RetransmitEvent struct {
	PID       uint32   // Process ID
	SAddr     uint32   // Source IPv4
	DAddr     uint32   // Dest IPv4
	SPort     uint16   // Source port
	DPort     uint16   // Dest port
	Family    uint16   // Address family (AF_INET=2, AF_INET6=10)
	_         uint16   // Padding
	Timestamp uint64   // Kernel timestamp
	Comm      [16]byte // Process name
}

func (e *RetransmitEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// ---------- TCP RST Events ----------

// RSTEvent mirrors the rst_event struct in bpf/tcp_rst.c.
type RSTEvent struct {
	PID       uint32   // Process ID
	SAddr     uint32   // Source IPv4
	DAddr     uint32   // Dest IPv4
	SPort     uint16   // Source port
	DPort     uint16   // Dest port
	Family    uint16   // Address family
	_         uint16   // Padding
	State     uint32   // TCP state at time of reset
	_pad2     uint32   // Padding
	Timestamp uint64   // Kernel timestamp
	Comm      [16]byte // Process name
}

func (e *RSTEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// ---------- OOM Events ----------

// OOMEvent mirrors the oom_event struct in bpf/oomkill.c.
type OOMEvent struct {
	PID         uint32   // Victim PID
	UID         uint32   // Victim UID
	TotalVM     uint64   // Total VM pages
	AnonRSS     uint64   // Anonymous RSS pages
	FileRSS     uint64   // File RSS pages
	ShmemRSS    uint64   // Shared memory RSS pages
	Pgtables    uint64   // Page table pages
	OOMScoreAdj int16    // OOM score adjustment
	_           uint16   // Padding
	_pad2       uint32   // Padding
	Timestamp   uint64   // Kernel timestamp
	Comm        [16]byte // Victim process name
}

func (e *OOMEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// TotalVMKB returns total VM in kilobytes.
func (e *OOMEvent) TotalVMKB() uint64 {
	pageSize := uint64(unsafe.Sizeof(uintptr(0))) * 1024 // approx
	if pageSize == 0 {
		pageSize = 4096
	}
	return e.TotalVM * 4 // pages to KB (4KB pages)
}

// ---------- Exec Events ----------

// ExecEvent mirrors the exec_event struct in bpf/exec_tracer.c.
type ExecEvent struct {
	PID       uint32    // New PID
	UID       uint32    // User ID
	OldPID    uint32    // Old PID (before exec)
	_         uint32    // Padding
	Timestamp uint64    // Kernel timestamp
	Comm      [16]byte  // Process name
	Filename  [128]byte // Executed filename
}

func (e *ExecEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

func (e *ExecEvent) FilenameString() string {
	for i, b := range e.Filename {
		if b == 0 {
			return string(e.Filename[:i])
		}
	}
	return string(e.Filename[:])
}

// ---------- File I/O Events ----------

// FileIOEvent mirrors the fileio_event struct in bpf/fileio_tracer.c.
type FileIOEvent struct {
	PID       uint32   // Process ID
	UID       uint32   // User ID
	LatencyNs uint64   // I/O latency in nanoseconds
	Bytes     uint64   // Bytes read/written (from return value)
	Timestamp uint64   // Kernel timestamp
	Op        uint8    // 0=read, 1=write
	_         [7]byte  // Padding
	Comm      [16]byte // Process name
}

func (e *FileIOEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

func (e *FileIOEvent) OpString() string {
	if e.Op == 0 {
		return "read"
	}
	return "write"
}

// ---------- Packet Drop Events ----------

// DropEvent mirrors the drop_event struct in bpf/drop_tracer.c.
type DropEvent struct {
	PID        uint32   // Process ID
	DropReason uint32   // enum skb_drop_reason
	Protocol   uint16   // Network protocol
	_          uint16   // Padding
	_pad2      uint32   // Padding
	Location   uint64   // Kernel function address
	Timestamp  uint64   // Kernel timestamp
	Comm       [16]byte // Process name
}

func (e *DropEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// DropReasonString returns human-readable drop reason.
func (e *DropEvent) DropReasonString() string {
	reasons := map[uint32]string{
		2:  "NOT_SPECIFIED",
		3:  "NO_SOCKET",
		4:  "PKT_TOO_SMALL",
		5:  "TCP_CSUM",
		6:  "SOCKET_FILTER",
		7:  "UDP_CSUM",
		8:  "NETFILTER_DROP",
		9:  "OTHERHOST",
		10: "IP_CSUM",
		11: "IP_INHDR",
		12: "IP_RPFILTER",
		16: "SOCKET_RCVBUFF",
		17: "PROTO_MEM",
		27: "TCP_FLAGS",
		28: "TCP_ZEROWINDOW",
		35: "TCP_RESET",
		37: "TCP_CLOSE",
		44: "IP_OUTNOROUTES",
		45: "BPF_CGROUP_EGRESS",
		47: "NEIGH_CREATEFAIL",
		48: "NEIGH_FAILED",
		51: "TC_EGRESS",
		52: "QDISC_DROP",
		55: "TC_INGRESS",
		63: "NOMEM",
	}
	if s, ok := reasons[e.DropReason]; ok {
		return s
	}
	return fmt.Sprintf("REASON_%d", e.DropReason)
}

// ---------- Helper Functions ----------

// FormatIPv4 converts a uint32 IPv4 address to dotted-decimal notation.
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
}
