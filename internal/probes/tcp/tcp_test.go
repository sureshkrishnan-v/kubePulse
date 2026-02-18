package tcp

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
	if m.Name() != constants.ModuleTCP {
		t.Errorf("Name() = %q, want %q", m.Name(), constants.ModuleTCP)
	}
}

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		ip   uint32
		want string
	}{
		{0x0100007F, "127.0.0.1"},
		{0, "0.0.0.0"},
	}
	for _, tt := range tests {
		got := bpfutil.FormatIPv4(tt.ip)
		if got != tt.want {
			t.Errorf("FormatIPv4(%#x) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestCommString(t *testing.T) {
	var c [constants.CommSize]byte
	copy(c[:], "curl")
	got := bpfutil.CommString(c)
	if got != "curl" {
		t.Errorf("CommString = %q, want %q", got, "curl")
	}
}
