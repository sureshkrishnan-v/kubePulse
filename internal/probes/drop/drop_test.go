package drop

import "testing"

func TestEvent_DropReasonString(t *testing.T) {
	tests := []struct {
		reason uint32
		want   string
	}{
		{2, "NOT_SPECIFIED"},
		{3, "NO_SOCKET"},
		{16, "NETFILTER_DROP"},
		{999, "REASON_999"},
	}
	for _, tt := range tests {
		e := Event{DropReason: tt.reason}
		if got := e.DropReasonString(); got != tt.want {
			t.Errorf("DropReasonString(%d) = %q, want %q", tt.reason, got, tt.want)
		}
	}
}
