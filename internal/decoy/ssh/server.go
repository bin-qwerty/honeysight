// Package ssh implements the SSH deception listener: a believable
// OpenSSH server that accepts any credentials, serves a fake interactive
// shell seeded with per-source canary tokens, and publishes every login
// and command as a pipeline event.
package ssh

import (
	"encoding/binary"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// ServerVersion is what the honeypot claims to be.
const ServerVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

// Server is the SSH deception listener.
type Server struct {
	log      *slog.Logger
	bus      *core.Bus
	tracker  *track.Tracker
	engine   *detect.Engine
	canaries *canary.Registry
	tarpit   time.Duration
	hostKey  gossh.Signer
}

// New builds the listener. canaries may be nil (no canary planting; the
// shell falls back to static fake values).
func New(log *slog.Logger, bus *core.Bus, tracker *track.Tracker, engine *detect.Engine, canaries *canary.Registry, tarpit time.Duration, hostKey gossh.Signer) *Server {
	if tarpit <= 0 {
		tarpit = 1500 * time.Millisecond
	}
	return &Server{
		log: log, bus: bus, tracker: tracker, engine: engine,
		canaries: canaries, tarpit: tarpit, hostKey: hostKey,
	}
}

// ListenAndServe accepts connections until the listener is closed.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log.Info("ssh decoy listening", "addr", addr)
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(raw)
	}
}

// metaConn carries per-connection context into the auth callbacks
// (the x/crypto callbacks only expose ConnMetadata).
type metaConn struct {
	ip      string
	port    int
	user    string
	set     *canary.Set
	version func() string // SSH client version, e.g. SSH-2.0-OpenSSH_8.9p1
}

// versionSniffConn records the client version line (the first bytes of
// every SSH connection) so events published during the handshake — before
// *ssh.ServerConn exists — can carry it.
type versionSniffConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	line string
	done bool
}

func (v *versionSniffConn) Read(p []byte) (int, error) {
	n, err := v.Conn.Read(p)
	v.mu.Lock()
	if !v.done && n > 0 {
		v.buf = append(v.buf, p[:n]...)
		if i := byteIndex(v.buf, '\n'); i >= 0 {
			v.line = strings.TrimRight(string(v.buf[:i]), "\r\n")
			v.done = true
			v.buf = nil
		} else if len(v.buf) > 256 {
			v.done = true // not a version line — give up
			v.buf = nil
		}
	}
	v.mu.Unlock()
	return n, err
}

func (v *versionSniffConn) version() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.line
}

func byteIndex(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func (s *Server) sshConfig(meta *metaConn) *gossh.ServerConfig {
	cfg := &gossh.ServerConfig{ServerVersion: ServerVersion}
	cfg.AddHostKey(s.hostKey)

	cfg.PasswordCallback = func(c gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
		s.publishLogin(meta, c.User(), "password", string(pass), "")
		return nil, nil // every credential "works"
	}

	cfg.PublicKeyCallback = func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		s.publishLogin(meta, c.User(), "publickey", "", gossh.FingerprintSHA256(key))
		return nil, nil // accept; the offered key fingerprint is an IOC
	}

	// Single "Password:" challenge that always works.
	cfg.KeyboardInteractiveCallback = func(c gossh.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		answers, err := client("", "", []string{"Password: "}, []bool{false})
		if err != nil {
			return nil, err
		}
		s.publishLogin(meta, c.User(), "keyboard-interactive", strings.Join(answers, " "), "")
		return nil, nil
	}
	return cfg
}

// publishLogin records a (fake) successful authentication attempt.
func (s *Server) publishLogin(meta *metaConn, user, method, pass, keyFP string) {
	ev := core.NewEvent("ssh", meta.ip, "login")
	ev.SourcePort = meta.port
	ev.Fingerprint = meta.version()
	ev.Details["user"] = user
	ev.Details["method"] = method
	if pass != "" {
		ev.Details["pass"] = pass
	}
	if keyFP != "" {
		ev.Details["key_fp"] = keyFP
	}
	det := s.engine.Analyze(detect.Fields{Body: user + " " + pass})
	ev.Enrich(det.Score, det.Categories)

	meta.user = user

	// The shell plants canaries; fetch the set up front so the login
	// event already carries the canary id.
	if s.canaries != nil {
		set := s.canaries.SetFor(meta.ip, "ssh_shell")
		ev.CanaryID = set.ID
		meta.set = set
	}

	s.bus.Publish(ev)
	s.log.Warn("ssh login", "id", ev.ID, "ip", meta.ip, "user", user, "method", method, "canary", ev.CanaryID)
}

// handleConn runs one SSH connection: handshake, then session channels.
func (s *Server) handleConn(raw net.Conn) {
	defer raw.Close()

	host, portStr, _ := net.SplitHostPort(raw.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)
	sniff := &versionSniffConn{Conn: raw}
	meta := &metaConn{ip: host, port: port, version: sniff.version}

	nsc, chans, reqs, err := gossh.NewServerConn(sniff, s.sshConfig(meta))
	if err != nil {
		return // not SSH or dropped before handshake — nothing to record
	}
	defer nsc.Close()

	// Banner grab: the version exchange has already happened.
	ev := core.NewEvent("ssh", meta.ip, "banner")
	ev.SourcePort = meta.port
	ev.Fingerprint = meta.version()
	s.bus.Publish(ev)

	// Global requests (keepalive etc.) — ack and discard.
	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(meta, ch, chReqs)
	}
}

// sendExitStatus notifies the client the command finished (RFC 4254 6.10);
// clients like OpenSSH wait for it before treating the channel as done.
func sendExitStatus(ch gossh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct {
		Status uint32
	}{status}))
}

// handleSession serves one "session" channel: pty/exec/shell requests and,
// for shell, the interactive loop.
func (s *Server) handleSession(meta *metaConn, ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer ch.Close()
	sess := newSession(s.log, meta.ip, meta.port, meta.user, meta.set, meta.version(), s.bus, s.engine, s.tracker, s.tarpit)

	for req := range reqs {
		switch req.Type {
		case "env", "pty-req", "window-change":
			if req.Type == "pty-req" {
				sess.term = ptyTerm(req.Payload)
			}
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			sess.runInteractive(ch)
			return
		case "exec":
			_ = req.Reply(true, nil)
			sess.runOnce(ch, execCommand(req.Payload))
			return
		case "subsystem":
			// sftp & co: not installed on this "machine".
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// execCommand decodes the exec request payload (uint32 length + string).
func execCommand(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload)
	if int(n) > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

// ptyTerm extracts the terminal type from a pty-req payload
// (term is the first string in the payload).
func ptyTerm(payload []byte) string {
	if len(payload) < 4 {
		return "xterm-256color"
	}
	n := int(binary.BigEndian.Uint32(payload[:4]))
	if n <= 0 || 4+n > len(payload) {
		return "xterm-256color"
	}
	if term := strings.TrimSpace(string(payload[4 : 4+n])); term != "" {
		return term
	}
	return "xterm-256color"
}
