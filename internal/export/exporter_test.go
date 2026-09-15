package export

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/enrich"
)

type fakeEnricher struct {
	m map[string]enrich.Enrichment
}

func (f fakeEnricher) Enrich(ip string) (enrich.Enrichment, bool) {
	g, ok := f.m[ip]
	return g, ok
}
func (fakeEnricher) Close() error { return nil }

func TestExporterBatchDelivery(t *testing.T) {
	type got struct {
		mu   sync.Mutex
		body []byte
	}
	var received got
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		received.mu.Lock()
		received.body = body
		received.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	exp := New(slog.New(slog.DiscardHandler), fakeEnricher{m: map[string]enrich.Enrichment{
		"1.2.3.4": {Country: "DE", City: "Berlin", ASN: 15169, ASOrg: "GOOGLE"},
	}}, Options{URL: srv.URL, BatchSize: 3, Interval: time.Hour, Retries: 1})
	exp.Start(time.Hour)
	defer exp.Stop()

	e1 := ev("1.2.3.4", "request", "sqlmap/1.8", 40, "sql-injection")
	e2 := ev("1.2.3.4", "login", "", 0)
	e3 := ev("5.6.7.8", "cmd", "", 85, "command-injection")
	exp.Handle(e1)
	exp.Handle(e2)
	// two events: not yet delivered
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		received.mu.Lock()
		none := received.body == nil
		received.mu.Unlock()
		if !none {
			t.Fatal("delivered before batch was full")
		}
		time.Sleep(10 * time.Millisecond)
	}
	exp.Handle(e3) // third event: batch full, flush

	// wait for delivery
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		received.mu.Lock()
		any := received.body != nil
		received.mu.Unlock()
		if any {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	received.mu.Lock()
	body := received.body
	received.mu.Unlock()
	if body == nil {
		t.Fatal("no delivery received")
	}

	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.Source != "honeysight" || env.EventCount != 3 || len(env.Events) != 3 {
		t.Fatalf("envelope = %+v", env)
	}
	if env.STIXBundle == nil || env.STIXBundle.Type != "bundle" {
		t.Fatal("stix_bundle missing")
	}

	// enrichment on the first event
	e := env.Events[0]
	if e.ID != e1.ID || e.Protocol != "http" || e.SourceIP != "1.2.3.4" {
		t.Errorf("event = %+v", e)
	}
	if e.Geo == nil || e.Geo.Country != "DE" || e.Geo.City != "Berlin" {
		t.Errorf("geo = %+v", e.Geo)
	}
	if e.ASN == nil || e.ASN.Number != 15169 || e.ASN.Org != "GOOGLE" {
		t.Errorf("asn = %+v", e.ASN)
	}
	// the 5.6.7.8 event has no enrichment
	last := env.Events[2]
	if last.Geo != nil || last.ASN != nil {
		t.Errorf("unexpected enrichment: geo=%+v asn=%+v", last.Geo, last.ASN)
	}
}

func TestExporterDropsOnPermanentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	exp := New(slog.New(slog.DiscardHandler), nil,
		Options{URL: srv.URL, BatchSize: 1, Interval: time.Hour, Retries: 1, Timeout: time.Second})
	exp.Start(time.Hour)
	defer exp.Stop()

	exp.Handle(ev("1.2.3.4", "request", "", 0))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && exp.Dropped() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if exp.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", exp.Dropped())
	}
}

func TestExporterRetrySucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := New(slog.New(slog.DiscardHandler), nil,
		Options{URL: srv.URL, BatchSize: 1, Interval: time.Hour, Retries: 3, Timeout: time.Second})
	exp.Start(time.Hour)
	defer exp.Stop()

	// The first retry sleeps 1s; allow time for attempt 2.
	go exp.Handle(ev("1.2.3.4", "request", "", 0))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if exp.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0 (retry should succeed)", exp.Dropped())
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

var _ core.Subscriber = (*Exporter)(nil)
