// Package core defines the normalized event model shared by all protocol
// listeners and pipeline subscribers.
package core

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Severity bands for a 0-100 threat score.
const (
	SevNone     = "none"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// SeverityFor maps a threat score to a severity band.
func SeverityFor(score int) string {
	switch {
	case score >= 80:
		return SevCritical
	case score >= 50:
		return SevHigh
	case score >= 25:
		return SevMedium
	case score > 0:
		return SevLow
	}
	return SevNone
}

// Event is a single normalized interaction captured by any protocol
// listener. Protocol-specific context lives in Details so the pipeline
// stays protocol-agnostic (http/ssh/redis today, more later).
type Event struct {
	ID          string
	Timestamp   time.Time
	Protocol    string // "http" | "ssh" | "redis"
	SourceIP    string
	SourcePort  int
	Action      string // "request", "login", "cmd", ...
	Details     map[string]string
	Score       int
	Categories  []string
	Severity    string
	CanaryID    string
	Fingerprint string // JA3/JA4 or other client fingerprints
}

// NewEvent builds an event with a random ID and current UTC timestamp.
func NewEvent(protocol, sourceIP, action string) Event {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return Event{
		ID:        hex.EncodeToString(b[:]),
		Timestamp: time.Now().UTC(),
		Protocol:  protocol,
		SourceIP:  sourceIP,
		Action:    action,
		Details:   map[string]string{},
		Severity:  SevNone,
	}
}

// Enrich sets detection results on the event.
func (e *Event) Enrich(score int, categories []string) {
	e.Score = score
	e.Categories = categories
	e.Severity = SeverityFor(score)
}
