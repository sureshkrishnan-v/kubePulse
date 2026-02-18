// Package bpfutil provides shared utilities for eBPF probe modules.
// Eliminates duplicated helper functions across probe packages.
package bpfutil

import (
	"bytes"
	"fmt"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
)

// CommString extracts a null-terminated command name from a fixed-size byte array.
func CommString(comm [constants.CommSize]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = len(comm)
	}
	return string(comm[:n])
}

// QNameString extracts a null-terminated DNS query name from a fixed-size byte array.
func QNameString(qname [constants.QNameSize]byte) string {
	n := bytes.IndexByte(qname[:], 0)
	if n < 0 {
		n = len(qname)
	}
	return string(qname[:n])
}

// FilenameString extracts a null-terminated filename from a fixed-size byte array.
func FilenameString(filename [constants.FilenameSize]byte) string {
	n := bytes.IndexByte(filename[:], 0)
	if n < 0 {
		n = len(filename)
	}
	return string(filename[:n])
}

// FormatIPv4 converts a uint32 IPv4 address to dotted-decimal string.
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// DropReasonString maps a kernel SKB drop reason code to a human-readable string.
// Uses the drop reasons table from the constants package.
func DropReasonString(reason uint32) string {
	if s, ok := constants.DropReasons[reason]; ok {
		return s
	}
	return fmt.Sprintf("REASON_%d", reason)
}
