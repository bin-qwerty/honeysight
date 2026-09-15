// Command honeysight runs the Honeysight deception honeypot:
// multi-protocol deception listeners feeding a single event pipeline.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/config"
	"github.com/honeysight/honeysight/internal/core"
	decoyssh "github.com/honeysight/honeysight/internal/decoy/ssh"
	"github.com/honeysight/honeysight/internal/decoy/web"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/fingerprint"
	"github.com/honeysight/honeysight/internal/store"
	"github.com/honeysight/honeysight/internal/store/sqlite"
	"github.com/honeysight/honeysight/internal/tlsutil"
	"github.com/honeysight/honeysight/internal/track"
)

// storeSub persists events; errors are logged, never fatal (fail-open).
type storeSub struct {
	log *slog.Logger
	s   store.Store
}

func (a storeSub) Name() string { return "store" }
func (a storeSub) Handle(e core.Event) {
	if err := a.s.Save(e); err != nil {
		a.log.Error("store save failed", "err", err, "id", e.ID)
	}
}

// logSub writes a structured line for every captured interaction
// (benign probes included — they are reconnaissance too).
type logSub struct{ log *slog.Logger }

func (a logSub) Name() string { return "log" }
func (a logSub) Handle(e core.Event) {
	a.log.Info("event",
		"id", e.ID, "proto", e.Protocol, "ip", e.SourceIP, "action", e.Action,
		"score", e.Score, "severity", e.Severity,
		"categories", strings.Join(e.Categories, ","),
		"fingerprint", e.Fingerprint, "canary", e.CanaryID, "details", e.Details,
	)
}

// trackerSub centralises per-source scoring and quarantine so every
// protocol listener shares the same logic.
type trackerSub struct {
	log *slog.Logger
	t   *track.Tracker
}

func (a trackerSub) Name() string { return "tracker" }
func (a trackerSub) Handle(e core.Event) {
	if e.Score <= 0 {
		return
	}
	st := a.t.Record(e.SourceIP, e.Score)
	if st.NewlyBlocked {
		a.log.Warn("source quarantined", "ip", e.SourceIP, "window_score", st.Score, "hits", st.Hits)
	}
}

func main() {
	configPath := flag.String("config", "config.yml", "path to YAML config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(log, "config", err)
	}
	engine, err := detect.Load(cfg.Rules.Path)
	if err != nil {
		fatal(log, "rules", err)
	}
	st, err := sqlite.Open(cfg.Storage.SQLitePath)
	if err != nil {
		fatal(log, "store", err)
	}

	canaryStore, err := canary.NewSQLiteStore(cfg.Storage.SQLitePath + "-canaries.db")
	if err != nil {
		fatal(log, "canary store", err)
	}
	canaries := canary.New(canaryStore, time.Hour)

	tracker := track.New(cfg.BlockThreshold, cfg.Window, cfg.BlockTTL)
	bus := core.NewBus(0, log,
		storeSub{log: log, s: st},
		logSub{log: log},
		trackerSub{log: log, t: tracker},
	)
	bus.Start()

	handler := web.New(log, bus, tracker, engine, canaries, cfg.TrustedProxies, cfg.Tarpit)
	srv := &http.Server{
		Addr:              cfg.Listen.HTTP,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 3)
	go func() { errCh <- srv.ListenAndServe() }()

	// Optional SSH listener: fake OpenSSH server with a canary-seeded shell.
	if cfg.Listen.SSH != "" {
		hostKey, err := decoyssh.EnsureHostKey(cfg.SSHHostKeyDir)
		if err != nil {
			fatal(log, "ssh host key", err)
		}
		sshSrv := decoyssh.New(log, bus, tracker, engine, canaries, cfg.Tarpit, hostKey)
		go func() { errCh <- sshSrv.ListenAndServe(cfg.Listen.SSH) }()
	}

	// Optional TLS listener: same handler, plus ClientHello (JA3) capture.
	if cfg.Listen.HTTPS != "" {
		certFile, keyFile, err := tlsutil.EnsureCert(cfg.TLSCertDir)
		if err != nil {
			fatal(log, "tls cert", err)
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fatal(log, "tls cert", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		ln, err := net.Listen("tcp", cfg.Listen.HTTPS)
		if err != nil {
			fatal(log, "https listen", err)
		}
		log.Info("https decoy listening", "addr", cfg.Listen.HTTPS, "cert", certFile)
		go func() {
			errCh <- fingerprint.Serve(ln, tlsCfg, func(h *fingerprint.Hello) http.Handler {
				return fingerprint.Decorate(handler, h)
			})
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		fatal(log, "listen", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", "err", err)
	}
	if err := st.Close(); err != nil {
		log.Error("store close", "err", err)
	}
	log.Info("bye")
}

func fatal(log *slog.Logger, what string, err error) {
	log.Error(what+" failed", "err", err)
	fmt.Fprintf(os.Stderr, "honeysight: %s: %v\n", what, err)
	os.Exit(1)
}
