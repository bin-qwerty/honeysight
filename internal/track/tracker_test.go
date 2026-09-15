package track

import (
	"testing"
	"time"
)

func TestAutoQuarantine(t *testing.T) {
	tr := New(100, time.Minute, time.Minute)
	s1 := tr.Record("1.1.1.1", 60)
	if s1.Blocked {
		t.Fatalf("blocked too early: %+v", s1)
	}
	s2 := tr.Record("1.1.1.1", 60)
	if !s2.Blocked || !s2.NewlyBlocked {
		t.Fatalf("expected new quarantine: %+v", s2)
	}
	if !tr.IsBlocked("1.1.1.1") {
		t.Fatal("IsBlocked=false after quarantine")
	}
	// Second block within the same hot window must not count as new.
	s3 := tr.Record("1.1.1.1", 10)
	if s3.NewlyBlocked {
		t.Fatalf("unexpected new block: %+v", s3)
	}
}

func TestWindowCoolOff(t *testing.T) {
	tr := New(100, 30*time.Millisecond, time.Minute)
	tr.Record("2.2.2.2", 60)
	tr.Record("2.2.2.2", 60) // blocked
	if !tr.IsBlocked("2.2.2.2") {
		t.Fatal("expected blocked")
	}
	// Quarantine TTL expires...
	tr2 := New(100, 30*time.Millisecond, 30*time.Millisecond)
	tr2.Record("3.3.3.3", 100)
	time.Sleep(60 * time.Millisecond)
	if tr2.IsBlocked("3.3.3.3") {
		t.Fatal("expected quarantine to expire")
	}
}

func TestSnapshot(t *testing.T) {
	tr := New(100, time.Minute, time.Minute)
	tr.Record("4.4.4.4", 40)
	snap := tr.Snapshot()
	if snap["tracked_sources"] != 1 {
		t.Fatalf("snapshot: %+v", snap)
	}
}
