package drop

import (
	"testing"

	"github.com/sureshkrishnan-v/kubePulse/internal/bpfutil"
	"github.com/sureshkrishnan-v/kubePulse/internal/constants"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.Name() != constants.ModuleDrop {
		t.Errorf("Name() = %q, want %q", m.Name(), constants.ModuleDrop)
	}
}

func TestDropReasonString(t *testing.T) {
	tests := []struct {
		reason uint32
		want   string
	}{
		{2, "NOT_SPECIFIED"},
		{3, "NO_SOCKET"},
		{99, "REASON_99"},
	}
	for _, tt := range tests {
		got := bpfutil.DropReasonString(tt.reason)
		if got != tt.want {
			t.Errorf("DropReasonString(%d) = %q, want %q", tt.reason, got, tt.want)
		}
	}
}
