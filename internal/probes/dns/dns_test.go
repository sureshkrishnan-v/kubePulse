package dns

import "testing"

func TestEvent_QNameString(t *testing.T) {
	event := Event{}
	copy(event.QName[:], "google.com")
	if got := event.QNameString(); got != "google.com" {
		t.Errorf("QNameString() = %q, want %q", got, "google.com")
	}
}

func TestEvent_QNameString_Empty(t *testing.T) {
	event := Event{}
	if got := event.QNameString(); got != "" {
		t.Errorf("QNameString() = %q, want empty", got)
	}
}

func TestTruncateDomain(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"www.google.com", "google.com"},
		{"a.b.c.d.example.org", "example.org"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := TruncateDomain(tt.input); got != tt.want {
				t.Errorf("TruncateDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
