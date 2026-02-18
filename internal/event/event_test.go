package event

import "testing"

func TestEventType_String(t *testing.T) {
	tests := []struct {
		t    EventType
		want string
	}{
		{TypeTCP, "tcp"},
		{TypeDNS, "dns"},
		{TypeRetransmit, "retransmit"},
		{TypeRST, "rst"},
		{TypeOOM, "oom"},
		{TypeExec, "exec"},
		{TypeFileIO, "fileio"},
		{TypeDrop, "drop"},
		{TypeUnknown, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestAcquire_Release(t *testing.T) {
	e := Acquire()
	if e == nil {
		t.Fatal("Acquire() returned nil")
	}
	e.Type = TypeTCP
	e.PID = 1234
	e.SetLabel("src", "10.0.0.1")
	e.SetNumeric("latency_ns", 42.0)

	if e.Label("src") != "10.0.0.1" {
		t.Error("Label not set")
	}
	if e.NumericVal("latency_ns") != 42.0 {
		t.Error("Numeric not set")
	}

	e.Release()

	// After release, re-acquire should give a clean event
	e2 := Acquire()
	if e2.Type != TypeUnknown {
		t.Error("Pool event not cleared")
	}
	if len(e2.Labels) != 0 {
		t.Error("Labels not cleared")
	}
	if len(e2.Numeric) != 0 {
		t.Error("Numeric not cleared")
	}
	e2.Release()
}

func TestBus_PublishSubscribe(t *testing.T) {
	bus := NewBus(16, nil)
	defer bus.Close()

	ch := bus.Subscribe("test")

	e := Acquire()
	e.Type = TypeTCP
	e.PID = 42
	bus.Publish(e)

	received := <-ch
	if received.Type != TypeTCP {
		t.Errorf("got type %v, want TypeTCP", received.Type)
	}
	if received.PID != 42 {
		t.Errorf("got PID %d, want 42", received.PID)
	}
}

func TestBus_DropOnOverflow(t *testing.T) {
	bus := NewBus(2, nil) // tiny buffer
	defer bus.Close()

	bus.Subscribe("slow")

	// Publish more than buffer can hold
	for i := 0; i < 10; i++ {
		e := Acquire()
		e.PID = uint32(i)
		bus.Publish(e)
	}

	stats := bus.Stats()
	if stats.Published != 10 {
		t.Errorf("published = %d, want 10", stats.Published)
	}
	// At least some should be dropped (buffer=2, published=10)
	dropped := stats.DroppedBySubscriber["slow"]
	if dropped == 0 {
		t.Error("expected drops, got 0")
	}
	if dropped != 8 {
		t.Errorf("dropped = %d, want 8", dropped)
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	bus := NewBus(16, nil)
	defer bus.Close()

	ch1 := bus.Subscribe("sub1")
	ch2 := bus.Subscribe("sub2")

	e := Acquire()
	e.Type = TypeOOM
	bus.Publish(e)

	r1 := <-ch1
	r2 := <-ch2
	if r1.Type != TypeOOM || r2.Type != TypeOOM {
		t.Error("both subscribers should receive the event")
	}
}

func BenchmarkBus_Publish(b *testing.B) {
	bus := NewBus(8192, nil)
	defer bus.Close()
	bus.Subscribe("bench")

	e := Acquire()
	e.Type = TypeTCP
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(e)
	}
}
