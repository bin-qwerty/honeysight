package canary

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSetStableWithinTTL(t *testing.T) {
	r := New(nil, time.Hour)
	a := r.SetFor("1.2.3.4", "admin")
	b := r.SetFor("1.2.3.4", "admin")
	if a.ID != b.ID {
		t.Error("same IP within TTL should get the same set")
	}
	c := r.SetFor("5.6.7.8", "admin")
	if c.ID == a.ID {
		t.Error("different IPs must get different sets")
	}
}

func TestSetRotatesAfterTTL(t *testing.T) {
	r := New(nil, time.Millisecond)
	a := r.SetFor("1.2.3.4", "admin")
	time.Sleep(5 * time.Millisecond)
	b := r.SetFor("1.2.3.4", "admin")
	if a.ID == b.ID {
		t.Error("set should rotate after TTL")
	}
}

func TestAllKindsGenerated(t *testing.T) {
	r := New(nil, time.Hour)
	s := r.SetFor("9.9.9.9", "x")
	for _, k := range AllKinds {
		if s.Value(k) == "" {
			t.Errorf("kind %s not generated", k)
		}
	}
	if got := s.Value(KindAWSAccess)[:4]; got != "AKIA" {
		t.Errorf("AWS key prefix = %q, want AKIA", got)
	}
	if len(s.Tokens()) != len(AllKinds) {
		t.Errorf("tokens = %d, want %d", len(s.Tokens()), len(AllKinds))
	}
}

func TestSQLiteRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canaries.db")
	st, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	r := New(st, time.Hour)
	s := r.SetFor("1.1.1.1", "admin")
	if err := st.SaveTokens(s.Tokens()); err != nil {
		t.Fatal(err)
	}
	// second open sees the rows
	st2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	rows, err := st2.db.Query(`SELECT COUNT(*) FROM canaries WHERE source_ip = '1.1.1.1'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	if !rows.Next() {
		t.Fatal("no rows")
	}
	if err := rows.Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(AllKinds) {
		t.Errorf("rows = %d, want %d", n, len(AllKinds))
	}
}
