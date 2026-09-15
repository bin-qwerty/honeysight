// Package enrich adds geographic and network context (country, city, ASN)
// to captured events using a local MaxMind .mmdb database. Honeysight never
// calls external enrichment services — the database file is provided by the
// operator and reads happen in memory.
package enrich

import (
	"fmt"
	"net"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Enrichment is the context attached to a source address.
type Enrichment struct {
	Country string // ISO 3166-1 alpha-2, e.g. "DE"
	City    string
	ASN     int    // autonomous system number, 0 = unknown
	ASOrg   string // AS organization name
}

// Enricher resolves context for source IPs.
type Enricher interface {
	// Enrich returns context for ip. ok is false when nothing is known.
	Enrich(ip string) (Enrichment, bool)
	// Close releases resources.
	Close() error
}

// noopEnricher is used when enrichment is disabled.
type noopEnricher struct{}

func (noopEnricher) Enrich(string) (Enrichment, bool) { return Enrichment{}, false }
func (noopEnricher) Close() error                     { return nil }

// MaxMind is a file-backed enricher with an in-memory IP cache.
type MaxMind struct {
	db    *maxminddb.Reader
	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	geo Enrichment
	ok  bool
}

// NewMaxMind opens the .mmdb file at path.
func NewMaxMind(path string) (*MaxMind, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}
	return &MaxMind{db: db, cache: make(map[string]cacheEntry)}, nil
}

// Enrich resolves ip against the database (cached per unique IP).
func (m *MaxMind) Enrich(ip string) (Enrichment, bool) {
	m.mu.Lock()
	if e, ok := m.cache[ip]; ok {
		m.mu.Unlock()
		return e.geo, e.ok
	}
	m.mu.Unlock()

	geo, ok := m.lookup(ip)

	m.mu.Lock()
	m.cache[ip] = cacheEntry{geo: geo, ok: ok}
	m.mu.Unlock()
	return geo, ok
}

func (m *MaxMind) lookup(ip string) (Enrichment, bool) {
	var ipNet net.IP
	if p := net.ParseIP(ip); p != nil {
		ipNet = p
	} else if host, _, err := net.SplitHostPort(ip); err == nil {
		ipNet = net.ParseIP(host)
	}
	if ipNet == nil {
		return Enrichment{}, false
	}

	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		ASNumber int    `maxminddb:"autonomous_system_number"`
		ASOrg    string `maxminddb:"autonomous_system_organization"`
	}
	if err := m.db.Lookup(ipNet, &rec); err != nil {
		return Enrichment{}, false
	}

	geo := Enrichment{
		Country: rec.Country.ISOCode,
		ASN:     rec.ASNumber,
		ASOrg:   rec.ASOrg,
	}
	if en, ok := rec.City.Names["en"]; ok {
		geo.City = en
	}
	if geo.Country == "" && geo.City == "" && geo.ASN == 0 && geo.ASOrg == "" {
		return Enrichment{}, false
	}
	return geo, true
}

// Close closes the database.
func (m *MaxMind) Close() error { return m.db.Close() }
