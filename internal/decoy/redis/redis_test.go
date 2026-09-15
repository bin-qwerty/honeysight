package redis

import (
	"bytes"

	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// --- RESP parser ---

func TestParseCommandSingleRead(t *testing.T) {
	data := []byte("*3\r\n$3\r\nGET\r\n$5\r\nmykey\r\n$2\r\n!?\r\n")
	rd := newReader(bytes.NewReader(data))
	cmd, err := rd.readCommand()
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil {
		t.Fatal("nil command")
	}
	if cmd.Name != "GET" || len(cmd.Args) != 2 || cmd.Args[0] != "mykey" {
		t.Fatalf("cmd = %+v", cmd)
	}
	if cmd.Raw != "GET mykey !?" {
		t.Errorf("raw = %q", cmd.Raw)
	}
}

func TestParseCommandChunked(t *testing.T) {
	// Feed the command byte-by-byte: the parser must reassemble.
	data := []byte("*2\r\n$4\r\nAUTH\r\n$7\r\ns3cr3t!\r\n")
	ch := make(chan byte, len(data))
	for _, b := range data {
		ch <- b
	}
	rd := newReader(chunkReader{ch: ch})
	cmd, err := rd.readCommand()
	if err != nil || cmd == nil {
		t.Fatalf("cmd=%v err=%v", cmd, err)
	}
	if cmd.Name != "AUTH" || cmd.Args[0] != "s3cr3t!" {
		t.Fatalf("cmd = %+v", cmd)
	}
}

type chunkReader struct{ ch chan byte }

func (c chunkReader) Read(p []byte) (int, error) {
	b, ok := <-c.ch
	if !ok {
		return 0, nil
	}
	p[0] = b
	return 1, nil
}

func TestParseInline(t *testing.T) {
	rd := newReader(strings.NewReader("GET foo\r\n"))
	cmd, err := rd.readCommand()
	if err != nil || cmd == nil {
		t.Fatalf("cmd=%v err=%v", cmd, err)
	}
	if cmd.Name != "GET" || cmd.Args[0] != "foo" {
		t.Fatalf("cmd = %+v", cmd)
	}
}

func TestParseTwoCommands(t *testing.T) {
	data := []byte("*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nSET\r\n$3\r\nbar\r\n")
	rd := newReader(bytes.NewReader(data))
	c1, err := rd.readCommand()
	if err != nil || c1.Name != "PING" {
		t.Fatalf("c1=%+v err=%v", c1, err)
	}
	c2, err := rd.readCommand()
	if err != nil || c2 == nil || c2.Name != "SET" {
		t.Fatalf("c2=%+v err=%v", c2, err)
	}
}

// --- full server round-trips ---

type memStore struct {
	mu     sync.Mutex
	tokens []canary.Token
}

func (m *memStore) SaveTokens(tk []canary.Token) error {
	m.mu.Lock()
	m.tokens = append(m.tokens, tk...)
	m.mu.Unlock()
	return nil
}

func newTestServer(t *testing.T) net.Listener {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	bus := core.NewBus(0, log) // no subscribers: fire and forget
	canaries := canary.New(&memStore{}, time.Hour)
	engine, err := detect.Load("../../../rules/default.yml")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	tracker := track.New(100, 5*time.Minute, 10*time.Minute)
	s := New(log, bus, tracker, engine, canaries, 50*time.Millisecond)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(raw)
		}
	}()
	return ln
}

// sendResp sends a raw command and reads one full reply.
func sendResp(t *testing.T, c net.Conn, cmd string) string {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(cmd)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out []byte
	buf := make([]byte, 65536)
	for {
		if complete(out) {
			return string(out)
		}
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return string(out) // connection closed
		}
	}
}

// complete reports whether out holds at least one full RESP reply.
func complete(out []byte) bool {
	if len(out) == 0 {
		return false
	}
	switch out[0] {
	case '+', '-', ':':
		return strings.Contains(string(out), "\r\n")
	case '$':
		i := strings.Index(string(out), "\r\n")
		if i < 0 {
			return false
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out[1:i])))
		if err != nil {
			return true
		}
		if n < 0 {
			return true
		}
		return len(out) >= i+2+n+2
	case '*':
		i := strings.Index(string(out), "\r\n")
		if i < 0 {
			return false
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out[1:i])))
		if err != nil {
			return true
		}
		if n < 0 {
			return true
		}
		rest, off := out[i+2:], i+2
		for k := 0; k < n; k++ {
			if len(rest) == 0 || rest[0] != '$' {
				return false
			}
			j := strings.Index(string(rest), "\r\n")
			if j < 0 {
				return false
			}
			m, err := strconv.Atoi(strings.TrimSpace(string(rest[1:j])))
			if err != nil || m < 0 {
				return true
			}
			if len(rest) < j+2+m+2 {
				return false
			}
			rest = rest[j+2+m+2:]
			off += j + 2 + m + 2
		}
		return off == len(out)
	}
	return false
}

func TestRedisAuthAndCanary(t *testing.T) {
	ln := newTestServer(t)
	defer ln.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if r := sendResp(t, c, "*2\r\n$4\r\nAUTH\r\n$8\r\nhunter22\r\n"); r != "+OK\r\n" {
		t.Fatalf("auth reply = %q", r)
	}
	// The keyspace is seeded with this source's canaries: values must be
	// non-null and stable across reads (same set, 1h TTL).
	r1 := sendResp(t, c, "*2\r\n$3\r\nGET\r\n$20\r\nnorthwind:api:secret\r\n")
	if !strings.HasPrefix(r1, "$") || strings.HasPrefix(r1, "$-1") {
		t.Fatalf("get reply = %q", r1)
	}
	r2 := sendResp(t, c, "*2\r\n$3\r\nGET\r\n$20\r\nnorthwind:api:secret\r\n")
	if r1 != r2 {
		t.Fatal("canary value changed between reads")
	}
}

func TestRedisCommands(t *testing.T) {
	ln := newTestServer(t)
	defer ln.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	cases := []struct {
		cmd  string
		want string // expected reply prefix
	}{
		{"*1\r\n$4\r\nPING\r\n", "+PONG"},
		{"*1\r\n$6\r\nDBSIZE\r\n", ":"},
		{"*1\r\n$4\r\nKEYS\r\n", "*"},
		{"*2\r\n$3\r\nGET\r\n$4\r\nnope\r\n", "$-1"},
		{"*2\r\n$3\r\nGET\r\n$15\r\nsession:counter\r\n", "$4\r\n1847"},
		{"*1\r\n$4\r\nINFO\r\n", "$"},
		{"*2\r\n$3\r\nSET\r\n$3\r\nbar\r\n", "+OK"},
		{"*1\r\n$5\r\nFLUSH\r\n", "-ERR"}, // unknown command
	}
	for i, tc := range cases {
		if r := sendResp(t, c, tc.cmd); !strings.HasPrefix(r, tc.want) {
			t.Errorf("case %d (%q): reply = %q, want prefix %q", i, tc.cmd, firstLine(r), tc.want)
		}
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i+2]
	}
	return s
}

func TestRedisAbuseDetected(t *testing.T) {
	engine, err := detect.Load("../../../rules/default.yml")
	if err != nil {
		t.Fatal(err)
	}
	if d := engine.Analyze(detect.Fields{Body: "FLUSHALL"}); d.Score == 0 {
		t.Fatal("FLUSHALL not detected")
	}
	if d := engine.Analyze(detect.Fields{Body: "CONFIG SET requirepass ''"}); d.Score == 0 {
		t.Fatal("CONFIG SET not detected")
	}
	if d := engine.Analyze(detect.Fields{Body: "GET foo"}); d.Score != 0 {
		t.Errorf("benign GET scored %d", d.Score)
	}
}

// TestMalformedBulkLengthDesync guards against a classic RESP desync:
// a short declared length must fail the connection, not bleed into the
// next command as a fake inline command.
func TestMalformedBulkLengthDesync(t *testing.T) {
	pkt := []byte("*2\r\n$4\r\nAUTH\r\n$6\r\nhunter2\r\n*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n")
	rd := newReader(bytes.NewReader(pkt))
	// The AUTH frame itself is malformed ($6 for "hunter2"): the parser
	// must reject the stream, not return a truncated password.
	cmd, err := rd.readCommand()
	if err == nil {
		t.Fatalf("expected protocol error, got cmd %+v", cmd)
	}
	if cmd != nil {
		t.Fatalf("expected no command on error, got %+v", cmd)
	}
}
