// Package web implements the HTTP deception listener: it serves believable
// bait while every request is captured, classified and published. All decoy
// content is fabricated — there are no real credentials or services behind it.
package web

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/fingerprint"
	"github.com/honeysight/honeysight/internal/track"
)

// maxBody bounds how much request body is profiled (memory-DoS guard).
const maxBody = 64 << 10

// Server is the HTTP deception listener.
type Server struct {
	log      *slog.Logger
	bus      *core.Bus
	tracker  *track.Tracker
	engine   *detect.Engine
	canaries *canary.Registry
	tarpit   time.Duration
	trusted  map[string]bool
}

// New builds the listener. trustedProxies are peer addresses allowed to
// supply X-Real-IP / X-Forwarded-For. canaries may be nil (no canary
// planting, the admin dashboard falls back to static values).
func New(log *slog.Logger, bus *core.Bus, tracker *track.Tracker, engine *detect.Engine, canaries *canary.Registry, trustedProxies []string, tarpit time.Duration) *Server {
	trusted := make(map[string]bool, len(trustedProxies))
	for _, p := range trustedProxies {
		trusted[p] = true
	}
	if tarpit <= 0 {
		tarpit = 1500 * time.Millisecond
	}
	return &Server{
		log: log, bus: bus, tracker: tracker, engine: engine, canaries: canaries,
		tarpit: tarpit, trusted: trusted,
	}
}

// setFingerprint records the TLS ClientHello (JA3) on the event, if the
// connection came in over the TLS listener.
func (s *Server) setFingerprint(ev *core.Event, r *http.Request) {
	if h := fingerprint.HelloFrom(r); h != nil {
		ev.Fingerprint = h.JA3()
	} else {
		ev.Fingerprint = "http/1.1"
	}
}

// clientIP derives the real source address. The peer is trusted as a proxy
// only if explicitly configured; otherwise header spoofing changes nothing.
func (s *Server) clientIP(r *http.Request) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, portStr = r.RemoteAddr, "0"
	}
	port, _ := strconv.Atoi(portStr)
	if !s.trusted[host] {
		return host, port
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return rip, 0
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0]), 0
	}
	return host, port
}

// ServeHTTP captures, classifies and publishes the request, then serves bait.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, port := s.clientIP(r)

	// Already quarantined: absorb with a slow 403 instead of more bait.
	if s.tracker.IsBlocked(ip) {
		time.Sleep(s.tarpit)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	path := r.URL.Path

	// Admin login first: it must read the raw form body itself, before
	// the generic capture below would consume it.
	if path == "/admin/login" && r.Method == http.MethodPost {
		s.handleLogin(w, r, ip, port)
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	body := string(bodyBytes)
	query := r.URL.RawQuery
	ua := r.UserAgent()

	ev := core.NewEvent("http", ip, "request")
	ev.SourcePort = port
	s.setFingerprint(&ev, r)
	ev.Details["method"] = r.Method
	ev.Details["path"] = path
	if query != "" {
		ev.Details["query"] = query
	}
	ev.Details["user_agent"] = ua
	if body != "" {
		ev.Details["body"] = body
	}

	det := s.engine.Analyze(detect.Fields{Path: path, Query: query, Body: body, UserAgent: ua})
	ev.Enrich(det.Score, det.Categories)

	// Admin dashboard pages plant canary tokens and mark the event with
	// the canary set; without a session cookie the login page is shown.
	if strings.HasPrefix(path, "/admin/") && r.Method == http.MethodGet {
		if c, err := r.Cookie(adminCookie); err == nil && c.Value != "" && s.canaries != nil {
			set := s.canaries.SetFor(ip, path)
			ev.CanaryID = set.ID
			s.bus.Publish(ev)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(renderDashboard(set))
			return
		}
		s.bus.Publish(ev)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fakeLogin))
		return
	}

	s.bus.Publish(ev) // tracker subscriber records the score centrally

	if det.IsMalicious() {
		s.log.Warn("interaction",
			"id", ev.ID, "ip", ip, "score", det.Score, "severity", ev.Severity,
			"categories", strings.Join(det.Categories, ","), "path", path,
		)
	}

	if bait, ok := decoyFor(path, r.Host); ok {
		w.Header().Set("Content-Type", bait.contentType)
		w.WriteHeader(bait.status)
		_, _ = w.Write(bait.body)
		return
	}
	http.Error(w, "404 Not Found", http.StatusNotFound)
}

// adminCookie is set after a (fake) successful login. Its value is the
// canary set id — the cookie itself is a canary.
const adminCookie = "ns_admin"

// handleLogin serves the fake IDaaS login: any credentials "work".
// The attempt (with credentials) is published, a canary cookie is set,
// and the client is sent to the data dashboard.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, ip string, port int) {
	_ = r.ParseForm()
	user := r.FormValue("user")
	pass := r.FormValue("pass")

	ev := core.NewEvent("http", ip, "login")
	ev.SourcePort = port
	s.setFingerprint(&ev, r)
	ev.Details["user"] = user
	ev.Details["pass"] = pass
	ev.Details["user_agent"] = r.UserAgent()
	det := s.engine.Analyze(detect.Fields{UserAgent: r.UserAgent(), Body: user + " " + pass})
	ev.Enrich(det.Score, det.Categories)

	var cookie *http.Cookie
	if s.canaries != nil {
		set := s.canaries.SetFor(ip, "/admin/login")
		ev.CanaryID = set.ID
		cookie = &http.Cookie{
			Name: adminCookie, Value: set.ID,
			Path: "/", MaxAge: 12 * 3600, HttpOnly: true,
		}
	}

	s.bus.Publish(ev)
	s.log.Warn("admin login", "id", ev.ID, "ip", ip, "user", user, "canary", ev.CanaryID)
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}
