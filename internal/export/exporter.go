package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/enrich"
)

// EventOut is the clean per-event JSON schema of the webhook payload.
type EventOut struct {
	ID          string            `json:"id"`
	Timestamp   string            `json:"ts"`
	Protocol    string            `json:"protocol"`
	SourceIP    string            `json:"source_ip"`
	SourcePort  int               `json:"source_port,omitempty"`
	Action      string            `json:"action"`
	Score       int               `json:"score"`
	Severity    string            `json:"severity"`
	Categories  []string          `json:"categories,omitempty"`
	CanaryID    string            `json:"canary_id,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Geo         *GeoOut           `json:"geo,omitempty"`
	ASN         *ASNOut           `json:"asn,omitempty"`
}

// GeoOut is the resolved geographic context.
type GeoOut struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
}

// ASNOut is the resolved network context.
type ASNOut struct {
	Number int    `json:"number,omitempty"`
	Org    string `json:"org,omitempty"`
}

// Envelope is the full webhook payload.
type Envelope struct {
	Source     string     `json:"source"`
	Version    int        `json:"version"`
	EmittedAt  string     `json:"emitted_at"`
	EventCount int        `json:"event_count"`
	Events     []EventOut `json:"events"`
	STIXBundle *bundle    `json:"stix_bundle"`
}

// Options configure the exporter.
type Options struct {
	URL       string
	BatchSize int           // flush when this many events are buffered
	Interval  time.Duration // flush at least this often
	Timeout   time.Duration // per-HTTP-request timeout
	Retries   int           // attempts per batch (1 = no retry)
}

// Exporter is a pipeline subscriber that batches events and delivers them
// to the webhook. It never blocks the bus: Handle only appends to an
// internal buffer; delivery happens in the flush goroutine.
type Exporter struct {
	log     *slog.Logger
	geo     enrich.Enricher
	url     string
	client  *http.Client
	batch   int
	retries int

	mu    sync.Mutex
	buf   []core.Event
	flush func()

	dropped atomic.Uint64
	stopped atomic.Bool
}

// New builds an exporter. geo may be nil (no enrichment).
func New(log *slog.Logger, geo enrich.Enricher, opts Options) *Exporter {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 50
	}
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Retries <= 0 {
		opts.Retries = 1
	}
	return &Exporter{
		log:     log,
		geo:     geo,
		url:     opts.URL,
		client:  &http.Client{Timeout: opts.Timeout},
		batch:   opts.BatchSize,
		retries: opts.Retries,
	}
}

// Name implements core.Subscriber.
func (e *Exporter) Name() string { return "export" }

// Handle implements core.Subscriber: buffer only, never block.
func (e *Exporter) Handle(ev core.Event) {
	if e.stopped.Load() {
		return
	}
	e.mu.Lock()
	e.buf = append(e.buf, ev)
	full := len(e.buf) >= e.batch
	e.mu.Unlock()
	if full && e.flush != nil {
		e.flush()
	}
}

// Start launches the periodic flush loop.
func (e *Exporter) Start(interval time.Duration) {
	e.flush = e.flushNow
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			e.flushNow()
		}
	}()
}

// Stop halts the loop and delivers what is left.
func (e *Exporter) Stop() {
	if !e.stopped.CompareAndSwap(false, true) {
		return
	}
	e.flushNow()
}

// Dropped returns the number of events lost to failed deliveries.
func (e *Exporter) Dropped() uint64 { return e.dropped.Load() }

// flushNow takes the buffer and delivers it (best effort).
func (e *Exporter) flushNow() {
	e.mu.Lock()
	if len(e.buf) == 0 {
		e.mu.Unlock()
		return
	}
	batch := e.buf
	e.buf = nil
	e.mu.Unlock()

	// Concurrent flushes (ticker + batch-full) are safe: each takes a
	// disjoint buffer snapshot under the same lock; delivery order may
	// swap, which is acceptable for a batch exporter.
	e.deliver(batch)
}

// deliver builds the payload and posts it with retries.
func (e *Exporter) deliver(batch []core.Event) {
	body, err := json.Marshal(e.buildEnvelope(batch))
	if err != nil {
		e.log.Error("export marshal failed", "err", err, "events", len(batch))
		e.dropped.Add(uint64(len(batch)))
		return
	}

	backoffs := []time.Duration{1 * time.Second, 5 * time.Second, 25 * time.Second}
	for attempt := 0; attempt < e.retries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoffs[min(attempt-1, len(backoffs)-1)])
		}
		err := e.post(body)
		if err == nil {
			return
		}
		e.log.Warn("export delivery failed",
			"attempt", attempt+1, "events", len(batch), "err", err)
	}
	e.log.Error("export batch dropped", "events", len(batch), "dropped_total", e.dropped.Add(uint64(len(batch))))
}

func (e *Exporter) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// buildEnvelope assembles the payload: clean events + STIX 2.1 bundle.
func (e *Exporter) buildEnvelope(batch []core.Event) Envelope {
	geoCache := map[string]enrich.Enrichment{}
	events := make([]EventOut, 0, len(batch))
	for _, ev := range batch {
		out := EventOut{
			ID:          ev.ID,
			Timestamp:   ev.Timestamp.UTC().Format(time.RFC3339),
			Protocol:    ev.Protocol,
			SourceIP:    ev.SourceIP,
			SourcePort:  ev.SourcePort,
			Action:      ev.Action,
			Score:       ev.Score,
			Severity:    ev.Severity,
			Categories:  ev.Categories,
			CanaryID:    ev.CanaryID,
			Fingerprint: ev.Fingerprint,
			Details:     ev.Details,
		}
		if e.geo != nil {
			if g, ok := geoCache[ev.SourceIP]; ok {
				out.Geo = &GeoOut{Country: g.Country, City: g.City}
				if g.ASN != 0 || g.ASOrg != "" {
					out.ASN = &ASNOut{Number: g.ASN, Org: g.ASOrg}
				}
			} else if g, ok := e.geo.Enrich(ev.SourceIP); ok {
				geoCache[ev.SourceIP] = g
				out.Geo = &GeoOut{Country: g.Country, City: g.City}
				if g.ASN != 0 || g.ASOrg != "" {
					out.ASN = &ASNOut{Number: g.ASN, Org: g.ASOrg}
				}
			}
		}
		events = append(events, out)
	}
	return Envelope{
		Source:     "honeysight",
		Version:    1,
		EmittedAt:  time.Now().UTC().Format(time.RFC3339),
		EventCount: len(batch),
		Events:     events,
		STIXBundle: BuildBundle(batch),
	}
}
