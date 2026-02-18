package metrics

import "testing"

func TestTruncateDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"www.api.google.com", "google.com"},
		{"kubernetes.default.svc.cluster.local", "cluster.local"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
		{"", "unknown"},
		{"a.b.c.d.example.org", "example.org"},
		{"single", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := TruncateDomain(tt.input)
			if result != tt.expected {
				t.Errorf("TruncateDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSplitDomainLabels(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"www.google.com", 3},
		{"example.com", 2},
		{"localhost", 1},
		{"a.b.c.d.e", 5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			labels := splitDomainLabels(tt.input)
			if len(labels) != tt.expected {
				t.Errorf("splitDomainLabels(%q) = %d labels, want %d", tt.input, len(labels), tt.expected)
			}
		})
	}
}

func BenchmarkTruncateDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TruncateDomain("www.api.google.com")
	}
}
