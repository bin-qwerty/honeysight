package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// --- event collector (same pattern as web tests) -------------------------

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

func (c *collector) snapshot() []core.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]core.Event, len(c.evs))
	copy(out, c.evs)
	return out
}

// waitFor polls until pred matches some event or the deadline passes.
func (c *collector) waitFor(t *testing.T, desc string, pred func(core.Event) bool) core.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range c.snapshot() {
			if pred(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event: %s", desc)
	return core.Event{}
}

// --- test server ----------------------------------------------------------

type testSrv struct {
	ln       net.Listener
	addr     string
	col      *collector
	canaries *canary.Registry
}

func startTestServer(t *testing.T) *testSrv {
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

	hostKey, err := EnsureHostKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(slog.New(slog.DiscardHandler), bus, tracker, engine, canaries, 50*time.Millisecond, hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serveFrom(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })
	return &testSrv{ln: ln, addr: ln.Addr().String(), col: col, canaries: canaries}
}

// serveFrom is ListenAndServe over a pre-bound listener (for tests).
func serveFrom(ln net.Listener, s *Server) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(raw)
	}
}

func dial(t *testing.T, addr, user string, auth gossh.AuthMethod) *gossh.Client {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{auth},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	c, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// streamReader feeds chunks of r to readers through a single goroutine,
// so readUntil can enforce a deadline even when no data arrives.
type streamReader struct {
	ch chan string
}

func newStreamReader(r io.Reader) *streamReader {
	s := &streamReader{ch: make(chan string, 16)}
	go func() {
		defer close(s.ch)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				s.ch <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

// readUntil accumulates new chunks until marker appears (or deadline).
func (s *streamReader) readUntil(t *testing.T, marker string) string {
	t.Helper()
	var acc strings.Builder
	deadline := time.After(5 * time.Second)
	for {
		if strings.Contains(acc.String(), marker) {
			return acc.String()
		}
		select {
		case chunk, ok := <-s.ch:
			if !ok {
				t.Fatalf("channel closed before %q, got %q", marker, acc.String())
			}
			acc.WriteString(chunk)
		case <-deadline:
			t.Fatalf("timed out waiting for %q, got %q", marker, acc.String())
		}
	}
}

// --- tests -----------------------------------------------------------------

func TestSSHPasswordLoginAndShell(t *testing.T) {
	srv := startTestServer(t)
	client := dial(t, srv.addr, "root", gossh.Password("hunter2"))

	// banner + login events
	banner := srv.col.waitFor(t, "banner", func(e core.Event) bool { return e.Action == "banner" })
	if banner.Protocol != "ssh" {
		t.Errorf("banner proto = %q", banner.Protocol)
	}
	login := srv.col.waitFor(t, "login", func(e core.Event) bool { return e.Action == "login" })
	if got := login.Details["user"]; got != "root" {
		t.Errorf("login user = %q", got)
	}
	if got := login.Details["pass"]; got != "hunter2" {
		t.Errorf("login pass = %q", got)
	}
	if got := login.Details["method"]; got != "password" {
		t.Errorf("login method = %q", got)
	}
	if login.Fingerprint == "" {
		t.Error("login event has no client-version fingerprint")
	}
	if login.CanaryID == "" {
		t.Error("login event has no canary id")
	}

	// interactive session: pty + shell
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	go func() {
		for range reqs {
		}
	}()

	if _, err := ch.SendRequest("pty-req", true, ptyReqPayload("xterm-256color")); err != nil {
		t.Fatal(err)
	}
	if ok, err := ch.SendRequest("shell", true, nil); !ok || err != nil {
		t.Fatalf("shell request: ok=%v err=%v", ok, err)
	}
	rd := newStreamReader(ch)

	prompt := "root@northwind-app01:~$ "
	rd.readUntil(t, prompt)

	if _, err := ch.Write([]byte("whoami\n")); err != nil {
		t.Fatal(err)
	}
	out := rd.readUntil(t, prompt)
	if !strings.Contains(out, "root") {
		t.Errorf("whoami output = %q", out)
	}

	// .env must contain THIS source's canary tokens
	set := srv.canaries.SetFor("127.0.0.1", "ssh_shell")
	if _, err := ch.Write([]byte("cat .env\n")); err != nil {
		t.Fatal(err)
	}
	out = rd.readUntil(t, prompt)
	if !strings.Contains(out, set.Value(canary.KindDBPassword)) {
		t.Errorf("cat .env missing DB password canary %q\noutput: %q", set.Value(canary.KindDBPassword), out)
	}
	if !strings.Contains(out, set.Value(canary.KindAPIKey)) {
		t.Errorf("cat .env missing API key canary")
	}

	// malicious command is detected
	if _, err := ch.Write([]byte("cat /etc/passwd; nc 10.9.9.9 4444\n")); err != nil {
		t.Fatal(err)
	}
	out = rd.readUntil(t, prompt)
	if !strings.Contains(out, set.Value(canary.KindUsername)) {
		t.Errorf("cat /etc/passwd missing username canary\noutput: %q", out)
	}
	cmdEv := srv.col.waitFor(t, "malicious cmd", func(e core.Event) bool {
		return e.Action == "cmd" && strings.Contains(e.Details["command"], "nc 10.9.9.9")
	})
	if cmdEv.Score == 0 {
		t.Error("malicious cmd got zero score")
	}
	hasCat := func(name string) bool {
		for _, c := range cmdEv.Categories {
			if c == name {
				return true
			}
		}
		return false
	}
	if !hasCat("command-injection") {
		t.Errorf("cmd categories = %v, want command-injection", cmdEv.Categories)
	}
	if cmdEv.CanaryID != set.ID {
		t.Errorf("cmd canary = %q, want %q", cmdEv.CanaryID, set.ID)
	}

	if _, err := ch.Write([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
}

func TestSSHPublicKeyLogin(t *testing.T) {
	srv := startTestServer(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	client := dial(t, srv.addr, "deploy", gossh.PublicKeys(signer))
	_ = client

	login := srv.col.waitFor(t, "publickey login", func(e core.Event) bool {
		return e.Action == "login" && e.Details["method"] == "publickey"
	})
	pub, _ := gossh.NewPublicKey(priv.Public())
	want := gossh.FingerprintSHA256(pub)
	if got := login.Details["key_fp"]; got != want {
		t.Errorf("key_fp = %q, want %q", got, want)
	}
}

func TestSSHExecOnce(t *testing.T) {
	srv := startTestServer(t)
	client := dial(t, srv.addr, "ubuntu", gossh.Password("pw"))

	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Output("uname -a")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if !strings.Contains(string(out), "northwind-app01") {
		t.Errorf("exec output = %q", out)
	}

	srv.col.waitFor(t, "exec cmd", func(e core.Event) bool {
		return e.Action == "cmd" && e.Details["command"] == "uname -a"
	})
}

// ptyReqPayload builds a pty-req channel request payload.
func ptyReqPayload(term string) []byte {
	var b []byte
	appendStr := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b = append(b, l[:]...)
		b = append(b, s...)
	}
	appendU32 := func(v uint32) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], v)
		b = append(b, l[:]...)
	}
	appendStr(term)
	appendU32(80)  // cols
	appendU32(24)  // rows
	appendU32(800) // width
	appendU32(240) // height
	appendStr("")  // modes
	return b
}
