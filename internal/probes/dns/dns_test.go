package dns

import (
	"testing"

	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.Name() != constants.ModuleDNS {
		t.Errorf("Name() = %q, want %q", m.Name(), constants.ModuleDNS)
	}
}

func TestTruncateDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"api.svc.cluster.local", "cluster.local"},
		{"example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
	}
	for _, tt := range tests {
		got := TruncateDomain(tt.domain)
		if got != tt.want {
			t.Errorf("TruncateDomain(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
