// Package export ships captured events to the operator's threat-intelligence
// pipeline: a clean JSON envelope plus a STIX 2.1 bundle, delivered in
// batches over an HTTP webhook. No external calls are made anywhere else —
// the webhook target is the only place Honeysight writes out.
package export

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/honeysight/honeysight/internal/core"
)

// STIXSpecVersion is the STIX version emitted in bundles.
const STIXSpecVersion = "2.1"

// uuid returns a random RFC 4122 version-4 UUID.
func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// stixObject is the common STIX object header.
type stixObject struct {
	Type        string `json:"type"`
	SpecVersion string `json:"spec_version"`
	ID          string `json:"id"`
	Version     int    `json:"version"`
}

// indicator is a STIX 2.1 indicator object (one per unique source IP).
type indicator struct {
	stixObject
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Pattern         string   `json:"pattern"`
	PatternType     string   `json:"pattern_type"`
	PatternVersion  string   `json:"pattern_version"`
	ValidFrom       string   `json:"valid_from"`
	IndicatorTypes  []string `json:"indicator_types"`
	Labels          []string `json:"labels"`
	Confidence      int      `json:"confidence"`
	HoneysightExtra any      `json:"x_honeysight"`
}

// tool is a STIX 2.1 tool object (scanner user-agents).
type tool struct {
	stixObject
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	ToolTypes       []string `json:"tool_types"`
	HoneysightExtra any      `json:"x_honeysight"`
}

// report ties the objects of one batch together.
type report struct {
	stixObject
	Name        string   `json:"name"`
	ReportTypes []string `json:"report_types"`
	Published   string   `json:"published"`
	ObjectRefs  []string `json:"object_refs"`
}

// bundle is a STIX 2.1 bundle.
type bundle struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	SpecVersion string `json:"spec_version"`
	Objects     []any  `json:"objects"`
}

// ipAgg accumulates per-IP facts for the indicator object.
type ipAgg struct {
	ip           string
	score        int
	categories   map[string]bool
	protocols    map[string]bool
	actions      map[string]bool
	canaries     map[string]bool
	fingerprints map[string]bool
	events       int
	firstSeen    time.Time
	lastSeen     time.Time
}

// BuildBundle converts a batch of events into a STIX 2.1 bundle:
// one indicator per unique source IP (max score, category union, seen
// window), one tool per scanner-like User-Agent, and a report referencing
// everything. Pure function.
func BuildBundle(events []core.Event) *bundle {
	byIP := map[string]*ipAgg{}
	tools := map[string]*toolInfo{}

	for _, e := range events {
		a := byIP[e.SourceIP]
		if a == nil {
			a = &ipAgg{
				ip: e.SourceIP, score: e.Score,
				categories: map[string]bool{}, protocols: map[string]bool{},
				actions: map[string]bool{}, canaries: map[string]bool{},
				fingerprints: map[string]bool{},
				firstSeen:    e.Timestamp, lastSeen: e.Timestamp,
			}
			byIP[e.SourceIP] = a
		}
		a.events++
		if e.Score > a.score {
			a.score = e.Score
		}
		if e.Timestamp.Before(a.firstSeen) {
			a.firstSeen = e.Timestamp
		}
		if e.Timestamp.After(a.lastSeen) {
			a.lastSeen = e.Timestamp
		}
		for _, c := range e.Categories {
			a.categories[c] = true
		}
		a.protocols[e.Protocol] = true
		a.actions[e.Action] = true
		if e.CanaryID != "" {
			a.canaries[e.CanaryID] = true
		}
		if e.Fingerprint != "" && e.Fingerprint != "http/1.1" {
			a.fingerprints[e.Fingerprint] = true
		}
		if ua := e.Details["user_agent"]; ua != "" && looksLikeScanner(ua) {
			t := tools[strings.ToLower(ua)]
			if t == nil {
				t = &toolInfo{ua: ua, sources: map[string]bool{}}
				tools[strings.ToLower(ua)] = t
			}
			t.sources[e.SourceIP] = true
		}
	}

	var objects []any
	var refs []string

	// Deterministic order for stable output.
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ip := range ips {
		a := byIP[ip]
		labels := make([]string, 0, len(a.categories))
		for c := range a.categories {
			labels = append(labels, c)
		}
		sort.Strings(labels)

		pattern := fmt.Sprintf("[ipv4-addr:value = '%s']", ip)
		if p := net.ParseIP(ip); p != nil && p.To4() == nil {
			pattern = fmt.Sprintf("[ipv6-addr:value = '%s']", ip)
		}

		obj := indicator{
			stixObject: stixObject{Type: "indicator", SpecVersion: STIXSpecVersion, ID: "indicator:" + uuid(), Version: 1},
			Name:       fmt.Sprintf("Honeysight source %s", ip),
			Description: fmt.Sprintf(
				"Attacker activity observed by Honeysight: %d events, score %d, first seen %s, last seen %s",
				a.events, a.score, a.firstSeen.UTC().Format(time.RFC3339), a.lastSeen.UTC().Format(time.RFC3339)),
			Pattern:        pattern,
			PatternType:    "stix",
			PatternVersion: STIXSpecVersion,
			ValidFrom:      a.firstSeen.UTC().Format(time.RFC3339),
			IndicatorTypes: []string{"ip-address"},
			Labels:         labels,
			Confidence:     a.score,
			HoneysightExtra: map[string]any{
				"score":        a.score,
				"severity":     core.SeverityFor(a.score),
				"events":       a.events,
				"protocols":    sortedKeys(a.protocols),
				"actions":      sortedKeys(a.actions),
				"first_seen":   a.firstSeen.UTC().Format(time.RFC3339),
				"last_seen":    a.lastSeen.UTC().Format(time.RFC3339),
				"canaries":     sortedKeys(a.canaries),
				"fingerprints": sortedKeys(a.fingerprints),
			},
		}
		objects = append(objects, obj)
		refs = append(refs, obj.ID)
	}

	for _, t := range tools {
		obj := tool{
			stixObject:  stixObject{Type: "tool", SpecVersion: STIXSpecVersion, ID: "tool:" + uuid(), Version: 1},
			Name:        scannerName(t.ua),
			Description: fmt.Sprintf("Scanner user-agent observed by Honeysight: %s", t.ua),
			ToolTypes:   []string{"attack"},
			HoneysightExtra: map[string]any{
				"user_agent": t.ua,
				"sources":    sortedKeys(t.sources),
			},
		}
		objects = append(objects, obj)
		refs = append(refs, obj.ID)
	}

	rep := report{
		stixObject:  stixObject{Type: "report", SpecVersion: STIXSpecVersion, ID: "report:" + uuid(), Version: 1},
		Name:        fmt.Sprintf("Honeysight batch: %d events, %d sources", len(events), len(ips)),
		ReportTypes: []string{"threat-intel-report"},
		Published:   time.Now().UTC().Format(time.RFC3339),
		ObjectRefs:  refs,
	}
	objects = append(objects, rep)

	return &bundle{
		Type:        "bundle",
		ID:          "bundle:" + uuid(),
		SpecVersion: STIXSpecVersion,
		Objects:     objects,
	}
}

type toolInfo struct {
	ua      string
	sources map[string]bool
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var scannerUAs = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus", "openvas",
	"burp", "dirbuster", "gobuster", "wfuzz", "hydra", "metasploit",
	"nuclei", "wpscan", "acunetix", "nessus", "qualys", "exploitdb",
}

// looksLikeScanner reports whether the User-Agent advertises a scanner.
func looksLikeScanner(ua string) bool {
	l := strings.ToLower(ua)
	for _, s := range scannerUAs {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// scannerName extracts a short tool name from a User-Agent.
func scannerName(ua string) string {
	l := strings.ToLower(ua)
	for _, s := range scannerUAs {
		if i := strings.Index(l, s); i >= 0 {
			return s
		}
	}
	return ua
}
