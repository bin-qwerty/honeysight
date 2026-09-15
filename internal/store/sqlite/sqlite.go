// Package sqlite implements the Store interface on a local SQLite file
// (pure Go driver, no cgo — single static binary).
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/store"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id          TEXT PRIMARY KEY,
	ts          TEXT NOT NULL,
	protocol    TEXT NOT NULL,
	source_ip   TEXT NOT NULL,
	source_port INTEGER NOT NULL DEFAULT 0,
	action      TEXT NOT NULL,
	score       INTEGER NOT NULL DEFAULT 0,
	severity    TEXT NOT NULL DEFAULT 'none',
	categories  TEXT NOT NULL DEFAULT '',
	details     TEXT NOT NULL DEFAULT '{}',
	canary_id   TEXT NOT NULL DEFAULT '',
	fingerprint TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (source_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_score ON events (score);
`

// SQLite is a file-backed event store.
type SQLite struct {
	db *sql.DB
}

var _ store.Store = (*SQLite)(nil)

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*SQLite, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: one writer
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &SQLite{db: db}, nil
}

// Save inserts one event.
func (s *SQLite) Save(e core.Event) error {
	cats := ""
	if len(e.Categories) > 0 {
		cats = joinComma(e.Categories)
	}
	details, err := json.Marshal(e.Details)
	if err != nil {
		details = []byte("{}")
	}
	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO events
		 (id, ts, protocol, source_ip, source_port, action, score, severity, categories, details, canary_id, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		e.Protocol, e.SourceIP, e.SourcePort, e.Action,
		e.Score, e.Severity, cats, string(details), e.CanaryID, e.Fingerprint,
	)
	return err
}

// Close closes the underlying database.
func (s *SQLite) Close() error { return s.db.Close() }

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
