// Package canary implements canary tokens: per-source sets of unique fake
// credentials (DB passwords, cloud keys, usernames, internal hosts) baked
// into decoys. When a canary value shows up later (in the attacker's own
// infrastructure, a paste, an exfil log), the source is confirmed.
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Kind is a canary token type.
type Kind string

const (
	KindDBPassword Kind = "db_password"
	KindAPIKey     Kind = "api_key"
	KindAWSAccess  Kind = "aws_access_key_id"
	KindAWSSecret  Kind = "aws_secret_access_key"
	KindUsername   Kind = "username"
	KindInternalIP Kind = "internal_ip"
)

// AllKinds is the full set generated per source.
var AllKinds = []Kind{KindDBPassword, KindAPIKey, KindAWSAccess, KindAWSSecret, KindUsername, KindInternalIP}

// Token is a single canary value.
type Token struct {
	ID        string
	Kind      Kind
	Value     string
	SourceIP  string
	Context   string // where it was planted, e.g. "admin_dashboard"
	CreatedAt time.Time
}

// Store persists tokens. Optional (nil = in-memory only).
type Store interface {
	SaveTokens(tokens []Token) error
}

// Set is the per-source collection of canaries.
type Set struct {
	ID     string
	IP     string
	values map[Kind]string
	tokens []Token
}

// Value returns the canary value for kind.
func (s *Set) Value(kind Kind) string { return s.values[kind] }

// Tokens returns all tokens in the set.
func (s *Set) Tokens() []Token { return s.tokens }

// Registry hands out per-source canary sets. A set is valid for ttl;
// the next request after expiry gets a fresh set (attacker may have
// rotated infrastructure).
type Registry struct {
	mu       sync.Mutex
	store    Store
	ttl      time.Duration
	sessions map[string]*session
}

type session struct {
	set     *Set
	expires time.Time
}

// New creates a registry. ttl <= 0 defaults to 1h.
func New(store Store, ttl time.Duration) *Registry {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Registry{store: store, ttl: ttl, sessions: make(map[string]*session)}
}

// SetFor returns (creating or refreshing on expiry) the canary set for ip.
func (r *Registry) SetFor(ip, contextPath string) *Set {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if s, ok := r.sessions[ip]; ok && now.Before(s.expires) {
		return s.set
	}
	set := r.newSet(ip, contextPath)
	r.sessions[ip] = &session{set: set, expires: now.Add(r.ttl)}
	return set
}

func (r *Registry) newSet(ip, contextPath string) *Set {
	id := randHex(8)
	set := &Set{ID: id, IP: ip, values: make(map[Kind]string)}
	var tokens []Token
	for _, kind := range AllKinds {
		v := generate(kind, id)
		set.values[kind] = v
		tokens = append(tokens, Token{
			ID:        id + "-" + string(kind),
			Kind:      kind,
			Value:     v,
			SourceIP:  ip,
			Context:   contextPath,
			CreatedAt: time.Now().UTC(),
		})
	}
	set.tokens = tokens
	if r.store != nil {
		_ = r.store.SaveTokens(tokens) // best-effort
	}
	return set
}

// generate produces a value that looks like real credential material.
func generate(kind Kind, setID string) string {
	switch kind {
	case KindDBPassword:
		return "Nw-" + randHex(4) + "-" + setID[:4] + "!" + randHex(4)
	case KindAPIKey:
		return "nk_live_" + randHex(24)
	case KindAWSAccess:
		return "AKIA" + randAlphaNumUpper(16)
	case KindAWSSecret:
		return randAlphaNumMixed(40)
	case KindUsername:
		pick := []string{"j.morgan", "a.chen", "svc_backup", "m.reyes", "d.kowalski"}
		return pick[randInt(len(pick))]
	case KindInternalIP:
		return fmt.Sprintf("10.0.3.%d", 2+randInt(248))
	}
	return randHex(16)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randAlphaNumUpper(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randAlphaNumMixed(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if v < 0 {
		v = -v
	}
	return v % n
}
