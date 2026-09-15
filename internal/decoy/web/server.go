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

	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// maxBody bounds how much request body is profiled (memory-DoS guard).
const maxBody = 64 << 10

// Server is the HTTP deception listener.
type Server struct {
	log     *slog.Logger
	bus     *core.Bus
	tracker *track.Tracker
	engine  *detect.Engine
	tarpit  time.Duration
	trusted map[string]bool
}

// New builds the listener. trustedProxies are peer addresses allowed to
// supply X-Real-IP / X-Forwarded-For.
func New(log *slog.Logger, bus *core.Bus, tracker *track.Tracker, engine *detect.Engine, trustedProxies []string, tarpit time.Duration) *Server {
	trusted := make(map[string]bool, len(trustedProxies))
	for _, p := range trustedProxies {
		trusted[p] = true
	}
	if tarpit <= 0 {
		tarpit = 1500 * time.Millisecond
	}
	return &Server{
		log: log, bus: bus, tracker: tracker, engine: engine,
		tarpit: tarpit, trusted: trusted,
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

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	body := string(bodyBytes)
	path := r.URL.Path
	query := r.URL.RawQuery
	ua := r.UserAgent()

	ev := core.NewEvent("http", ip, "request")
	ev.SourcePort = port
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
