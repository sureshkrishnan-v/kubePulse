package probes

import "testing"

func TestTCPEvent_CommString(t *testing.T) {
	event := TCPEvent{
		Comm: [16]byte{'c', 'u', 'r', 'l', 0},
	}
	if got := event.CommString(); got != "curl" {
		t.Errorf("CommString() = %q, want %q", got, "curl")
	}
}

func TestTCPEvent_CommString_Full(t *testing.T) {
	event := TCPEvent{
		Comm: [16]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
	}
	if got := event.CommString(); got != "abcdefghijklmnop" {
		t.Errorf("CommString() = %q, want %q", got, "abcdefghijklmnop")
	}
}

func TestDNSEvent_QNameString(t *testing.T) {
	event := DNSEvent{
		QNameLen: 10,
	}
	copy(event.QName[:], "google.com")
	if got := event.QNameString(); got != "google.com" {
		t.Errorf("QNameString() = %q, want %q", got, "google.com")
	}
}

func TestDNSEvent_QNameString_Empty(t *testing.T) {
	event := DNSEvent{
		QNameLen: 0,
	}
	if got := event.QNameString(); got != "" {
		t.Errorf("QNameString() = %q, want empty", got)
	}
}

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		ip       uint32
		expected string
	}{
		{0x0100007F, "127.0.0.1"}, // 127.0.0.1 in little-endian
		{0x08080808, "8.8.8.8"},   // 8.8.8.8
		{0x00000000, "0.0.0.0"},   // 0.0.0.0
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatIPv4(tt.ip)
			if result != tt.expected {
				t.Errorf("FormatIPv4(%d) = %q, want %q", tt.ip, result, tt.expected)
			}
		})
	}
}
