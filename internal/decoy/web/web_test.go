package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

type collector struct {
	mu  sync.Mutex
	evs []core.Event
}

func (c *collector) Name() string { return "collector" }
func (c *collector) Handle(e core.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, e)
}

func (c *collector) wait(t *testing.T, n int) []core.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.evs) >= n {
			out := make([]core.Event, len(c.evs))
			copy(out, c.evs)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events (have %d)", n, len(c.evs))
	return nil
}

func newTestServer(t *testing.T) (*Server, *httptest.Server, *collector) {
	t.Helper()
	engine, err := detect.Load("../../../rules/default.yml")
	if err != nil {
		t.Fatal(err)
	}
	col := &collector{}
	bus := core.NewBus(64, slog.New(slog.DiscardHandler), col)
	bus.Start()
	tracker := track.New(100, 5*time.Minute, 10*time.Minute)
	canaries := canary.New(nil, time.Hour)
	srv := New(slog.New(slog.DiscardHandler), bus, tracker, engine, canaries, nil, 50*time.Millisecond)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); bus.Stop() })
	return srv, ts, col
}

func TestAdminLoginFlow(t *testing.T) {
	_, ts, col := newTestServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Login with fake credentials.
	res, err := client.PostForm(ts.URL+"/admin/login", map[string][]string{
		"user": {"admin"}, "pass": {"hunter2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// The client follows the 302, so the final response is the dashboard.
	if res.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", res.StatusCode)
	}
	if !strings.HasSuffix(res.Request.URL.Path, "/admin/dashboard") {
		t.Fatalf("final URL = %q, want dashboard", res.Request.URL)
	}
	dashboard := string(loginBody)
	if !strings.Contains(dashboard, "Northwind Admin Console") {
		t.Error("dashboard not rendered after login")
	}
	if !strings.Contains(dashboard, "Nw-") {
		t.Error("canary DB password not found in dashboard")
	}

	// 2. Login event captured with credentials.
	evs := col.wait(t, 1)
	var login *core.Event
	for i := range evs {
		if evs[i].Action == "login" {
			login = &evs[i]
		}
	}
	if login == nil {
		t.Fatal("no login event")
	}
	if login.Details["user"] != "admin" || login.Details["pass"] != "hunter2" {
		t.Errorf("login details = %v", login.Details)
	}
	if login.CanaryID == "" {
		t.Error("login event should carry the canary set id")
	}

	// 3. Dashboard behind the cookie contains the planted canaries.
	res, err = client.Get(ts.URL + "/admin/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", res.StatusCode)
	}
	page := string(body)
	if !strings.Contains(page, "Northwind Admin Console") {
		t.Error("dashboard page not rendered")
	}
	// The DB password canary (Nw- prefix) must be present.
	if !strings.Contains(page, "Nw-") {
		t.Error("canary DB password not found in dashboard")
	}

	// 4. Same set on the second page (stable within TTL).
	res2, _ := client.Get(ts.URL + "/admin/servers")
	if res2 == nil {
		t.Fatal("nil response")
	}
	page2, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	both := col.wait(t, 4)
	var dash1, dash2 string
	for _, e := range both {
		if e.Details["path"] == "/admin/dashboard" {
			dash1 = e.CanaryID
		}
		if e.Details["path"] == "/admin/servers" {
			dash2 = e.CanaryID
		}
	}
	if dash1 == "" || dash1 != dash2 {
		t.Errorf("canary ids: dashboard=%q servers=%q, want equal non-empty", dash1, dash2)
	}
	_ = page2
}

func TestDashboardWithoutCookieShowsLogin(t *testing.T) {
	_, ts, _ := newTestServer(t)
	res, err := ts.Client().Get(ts.URL + "/admin/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "Sign in") {
		t.Error("expected login page for unauthenticated dashboard access")
	}
}

func TestFingerprintPlainHTTP(t *testing.T) {
	_, ts, col := newTestServer(t)
	res, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	evs := col.wait(t, 1)
	if evs[0].Fingerprint != "http/1.1" {
		t.Errorf("fingerprint = %q, want http/1.1", evs[0].Fingerprint)
	}
}
