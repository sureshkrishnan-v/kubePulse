package tcp

import "testing"

func TestEvent_CommString(t *testing.T) {
	event := Event{Comm: [16]byte{'c', 'u', 'r', 'l', 0}}
	if got := event.CommString(); got != "curl" {
		t.Errorf("CommString() = %q, want %q", got, "curl")
	}
}

func TestEvent_CommString_Full(t *testing.T) {
	event := Event{
		Comm: [16]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
	}
	if got := event.CommString(); got != "abcdefghijklmnop" {
		t.Errorf("CommString() = %q, want %q", got, "abcdefghijklmnop")
	}
}

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		ip       uint32
		expected string
	}{
		{0x0100007F, "127.0.0.1"},
		{0x08080808, "8.8.8.8"},
		{0x00000000, "0.0.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := FormatIPv4(tt.ip); got != tt.expected {
				t.Errorf("FormatIPv4(%d) = %q, want %q", tt.ip, got, tt.expected)
			}
		})
	}
}
