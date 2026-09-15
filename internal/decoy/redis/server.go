// Package redis implements the Redis deception listener: a believable
// Redis 7.2 server that accepts any AUTH, serves a fake keyspace seeded
// with per-source canary tokens, and publishes every command as a
// pipeline event.
package redis

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// Server is the Redis deception listener.
type Server struct {
	log      *slog.Logger
	bus      *core.Bus
	tracker  *track.Tracker
	engine   *detect.Engine
	canaries *canary.Registry
	tarpit   time.Duration
}

// New builds the listener. canaries may be nil (static fake values).
func New(log *slog.Logger, bus *core.Bus, tracker *track.Tracker, engine *detect.Engine, canaries *canary.Registry, tarpit time.Duration) *Server {
	if tarpit <= 0 {
		tarpit = 1500 * time.Millisecond
	}
	return &Server{
		log: log, bus: bus, tracker: tracker, engine: engine,
		canaries: canaries, tarpit: tarpit,
	}
}

// ListenAndServe accepts connections until the listener is closed.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log.Info("redis decoy listening", "addr", addr)
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(raw)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	defer raw.Close()

	host, portStr, _ := net.SplitHostPort(raw.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)

	var set *canary.Set
	if s.canaries != nil {
		set = s.canaries.SetFor(host, "redis")
	}
	ks := newKeyspace(set)

	ev := core.NewEvent("redis", host, "connect")
	ev.SourcePort = port
	ev.Details["redis_version"] = RedisVersion
	s.bus.Publish(ev)

	rd := newReader(raw)
	for {
		cmd, err := rd.readCommand()
		if err != nil || cmd == nil {
			return
		}
		s.serve(raw, host, port, ks, cmd, set)
	}
}

// serve executes one command: detection, tarpit for quarantined sources,
// reply, event.
func (s *Server) serve(w net.Conn, ip string, port int, ks *keyspace, cmd *Command, set *canary.Set) {
	// AUTH is captured separately (it is the credential grab).
	if cmd.Name == "AUTH" {
		s.publishAuth(ip, port, cmd)
		writeSimpleString(w, "OK")
		return
	}

	// Detection + event for every other command.
	ev := core.NewEvent("redis", ip, "cmd")
	ev.SourcePort = port
	ev.Details["command"] = cmd.Name
	if len(cmd.Args) > 0 {
		ev.Details["arg0"] = cmd.Args[0]
	}
	if set != nil {
		ev.CanaryID = set.ID
	}
	det := s.engine.Analyze(detect.Fields{Body: cmd.Raw})
	ev.Enrich(det.Score, det.Categories)

	// Quarantined sources are slowed down, per reply.
	if s.tracker != nil && s.tracker.IsBlocked(ip) {
		time.Sleep(s.tarpit)
	}

	if err := s.reply(w, ks, cmd); err != nil {
		return
	}

	s.bus.Publish(ev)
	if ev.Score > 0 {
		s.log.Warn("redis cmd", "id", ev.ID, "ip", ip, "score", ev.Score,
			"severity", ev.Severity, "categories", strings.Join(ev.Categories, ","),
			"cmd", cmd.Raw)
	}
}

// reply produces the fake response for a command.
func (s *Server) reply(w net.Conn, ks *keyspace, cmd *Command) error {
	switch cmd.Name {
	case "PING":
		return writeSimpleString(w, "PONG")
	case "ECHO":
		if len(cmd.Args) > 0 {
			return WriteBulkString(w, cmd.Args[0])
		}
		return writeError(w, "ERR wrong number of arguments for 'echo' command")
	case "SELECT":
		return writeInteger(w, 1)
	case "QUIT":
		if err := writeSimpleString(w, "OK"); err != nil {
			return err
		}
		return nil // the client closes
	case "INFO":
		return WriteBulkString(w, ks.info())
	case "DBSIZE":
		return writeInteger(w, int64(ks.size()))
	case "KEYS":
		return WriteArray(w, ks.keys)
	case "SCAN":
		// "SCAN cursor [MATCH pattern]" — answer with a fresh cursor 0.
		return WriteArray(w, append([]string{"0"}, ks.keys...))
	case "GET":
		if len(cmd.Args) == 0 {
			return writeError(w, "ERR wrong number of arguments for 'get' command")
		}
		v, ok := ks.get(cmd.Args[0])
		if !ok {
			return nilBulk(w)
		}
		return WriteBulkString(w, v)
	case "EXISTS":
		if len(cmd.Args) == 0 {
			return writeInteger(w, 0)
		}
		if _, ok := ks.get(cmd.Args[0]); ok {
			return writeInteger(w, 1)
		}
		return writeInteger(w, 0)
	case "TTL":
		if len(cmd.Args) > 0 {
			if _, ok := ks.get(cmd.Args[0]); ok {
				return writeInteger(w, 3600)
			}
		}
		return writeInteger(w, -2)
	case "TYPE":
		if len(cmd.Args) > 0 {
			if _, ok := ks.get(cmd.Args[0]); ok {
				return writeSimpleString(w, "string")
			}
		}
		return writeError(w, "ERR key does not exist")
	case "STRLEN":
		if len(cmd.Args) > 0 {
			if v, ok := ks.get(cmd.Args[0]); ok {
				return writeInteger(w, int64(len(v)))
			}
		}
		return writeInteger(w, 0)
	case "SET":
		return writeSimpleString(w, "OK")
	case "MGET":
		return WriteArray(w, mget(ks, cmd.Args))
	case "MSET":
		return writeSimpleString(w, "OK")
	case "CONFIG":
		if len(cmd.Args) > 0 && strings.EqualFold(cmd.Args[0], "GET") {
			return WriteArray(w, configGet())
		}
		if len(cmd.Args) > 0 && strings.EqualFold(cmd.Args[0], "SET") {
			// "works" — the machine is not real.
			return writeSimpleString(w, "OK")
		}
		return writeError(w, "ERR wrong number of arguments for 'config' command")
	case "CLIENT":
		return writeSimpleString(w, "OK")
	case "COMMAND":
		return writeError(w, "ERR unknown subcommand or wrong number of arguments for 'command'")
	case "FLUSHALL", "FLUSHDB":
		return writeSimpleString(w, "OK")
	case "SHUTDOWN":
		// Do not actually close: scanners often just probe.
		return writeError(w, "ERR SHUTDOWN in progress")
	case "DEBUG":
		return writeError(w, "ERR DEBUG command not allowed on this instance")
	case "SLAVEOF", "REPLICAOF":
		return writeSimpleString(w, "OK")
	case "EVAL", "EVALSHA":
		return writeError(w, "NOSCRIPT No matching script. Please use EVAL.")
	case "SUBSCRIBE":
		return WriteArray(w, []string{"subscribe", orNone(cmd.Args), "0"})
	case "PSUBSCRIBE":
		return WriteArray(w, []string{"psubscribe", orNone(cmd.Args), "0"})
	default:
		return writeError(w, "ERR unknown command '"+cmd.Name+"'")
	}
}

func mget(ks *keyspace, keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if v, ok := ks.get(k); ok {
			out = append(out, v)
		}
	}
	return out
}

func orNone(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// publishAuth records the (fake) AUTH: the credential grab of this decoy.
func (s *Server) publishAuth(ip string, port int, cmd *Command) {
	method := "default"
	user, pass := "default", ""
	switch len(cmd.Args) {
	case 1:
		pass = cmd.Args[0]
	case 2:
		user, pass = cmd.Args[0], cmd.Args[1]
		method = "user"
	}

	ev := core.NewEvent("redis", ip, "auth")
	ev.SourcePort = port
	ev.Details["user"] = user
	if pass != "" {
		ev.Details["pass"] = pass
	}
	ev.Details["method"] = method

	// The keyspace carries this source's canaries; link the auth event.
	if s.canaries != nil {
		ev.CanaryID = s.canaries.SetFor(ip, "redis").ID
	}
	det := s.engine.Analyze(detect.Fields{Body: user + " " + pass})
	ev.Enrich(det.Score, det.Categories)

	s.bus.Publish(ev)
	s.log.Warn("redis auth", "id", ev.ID, "ip", ip, "user", user, "canary", ev.CanaryID)
}
