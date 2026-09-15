package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// replayConn replays already-captured bytes before falling back to the
// underlying connection, so the TLS handshake sees the exact original
// byte stream.
type replayConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	return c.Conn.Read(p)
}

// Capture reads whatever the client has already sent (up to a full
// ClientHello, best-effort) without blocking longer than wait.
func Capture(c net.Conn, wait time.Duration) []byte {
	var buf bytes.Buffer
	_ = c.SetReadDeadline(time.Now().Add(wait))
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if ParseClientHello(buf.Bytes()) != nil {
				break
			}
		}
		if err != nil {
			break // timeout or error: return what we have
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return buf.Bytes()
}

type ctxKey int

const helloKey ctxKey = 0

// Decorate wraps a handler so that HelloFrom(r) returns the captured
// ClientHello for that connection.
func Decorate(next http.Handler, h *Hello) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), helloKey, h)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HelloFrom returns the captured ClientHello, if any (TLS listener only).
func HelloFrom(r *http.Request) *Hello {
	v, _ := r.Context().Value(helloKey).(*Hello)
	return v
}

// Serve runs the handler over TLS on ln, capturing the ClientHello of each
// connection before the handshake. Each connection gets its own
// http.Server (a honeypot sees little traffic; the tarpit does the work).
// Connections that do not speak TLS are closed quietly.
func Serve(ln net.Listener, cfg *tls.Config, factory func(*Hello) http.Handler) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(raw, cfg, factory)
	}
}

func handleConn(raw net.Conn, cfg *tls.Config, factory func(*Hello) http.Handler) {
	defer raw.Close()

	data := Capture(raw, 300*time.Millisecond)
	hello := ParseClientHello(data)
	if hello == nil {
		return // not TLS — drop
	}

	tc := tls.Server(&replayConn{Conn: raw, buf: bytes.NewBuffer(data)}, cfg)
	hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})

	// Serve blocks until this connection is done, so raw is not closed
	// (by the deferred Close) while the handler is still using it.
	done := make(chan struct{})
	nc := &closeNotifyConn{Conn: tc, done: done}
	srv := &http.Server{
		Handler:           factory(hello),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	_ = srv.Serve(&oneShotListener{conn: nc, done: done})
}

// closeNotifyConn closes done on Close, so the accept loop below knows
// when the single connection's lifetime is over.
type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// oneShotListener yields exactly one connection, then blocks until it is
// closed — the shape http.Server.Serve needs for a pre-accepted connection.
type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if !l.once {
		l.once = true
		return l.conn, nil
	}
	<-l.done
	return nil, errors.New("no more connections")
}

func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

var _ net.Listener = (*oneShotListener)(nil)
