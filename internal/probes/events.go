// Package probes provides event structures and ring buffer consumers for eBPF probes.
package probes

// TCPEvent mirrors the tcp_event struct defined in bpf/tcp_tracer.c.
// Field layout MUST be byte-identical to the C struct for correct ring buffer reads.
type TCPEvent struct {
	PID       uint32    // Process ID
	UID       uint32    // User ID
	SAddr     uint32    // Source IPv4 address (network byte order)
	DAddr     uint32    // Destination IPv4 address (network byte order)
	SPort     uint16    // Source port (host byte order)
	DPort     uint16    // Destination port (host byte order)
	LatencyNs uint64    // Connection latency in nanoseconds
	Timestamp uint64    // Kernel timestamp (ktime_get_ns)
	Comm      [16]byte  // Process command name
}

// DNSEvent mirrors the dns_event struct defined in bpf/dns_tracer.c (Phase 2).
// Field layout MUST be byte-identical to the C struct for correct ring buffer reads.
type DNSEvent struct {
	PID       uint32     // Process ID
	UID       uint32     // User ID
	SAddr     uint32     // Source IPv4 address
	DAddr     uint32     // Destination IPv4 address (DNS server)
	SPort     uint16     // Source port
	DPort     uint16     // Destination port (53)
	LatencyNs uint64     // DNS query latency in nanoseconds
	Timestamp uint64     // Kernel timestamp
	QName     [256]byte  // DNS query name (dot-separated, null-terminated)
	QNameLen  uint16     // Length of the query name
	Comm      [16]byte   // Process command name
	_         [6]byte    // Padding for alignment
}

// CommString returns the process name as a Go string, trimming null bytes.
func (e *TCPEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// CommString returns the process name as a Go string, trimming null bytes.
func (e *DNSEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// QNameString returns the DNS query name as a Go string, trimming null bytes.
func (e *DNSEvent) QNameString() string {
	if e.QNameLen == 0 {
		return ""
	}
	n := int(e.QNameLen)
	if n > len(e.QName) {
		n = len(e.QName)
	}
	return string(e.QName[:n])
}
