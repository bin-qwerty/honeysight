package canary

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore persists canary tokens (for post-hoc "canary hit"
// correlation: when a value is found in the wild, look up its source IP).
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (creating if needed) the canary table in path.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS canaries (
	id         TEXT PRIMARY KEY,
	kind       TEXT NOT NULL,
	value      TEXT NOT NULL,
	source_ip  TEXT NOT NULL,
	context    TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	hit_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_canaries_value ON canaries(value);
CREATE INDEX IF NOT EXISTS idx_canaries_ip ON canaries(source_ip, created_at);
`)
	return err
}

// SaveTokens implements Store.
func (s *SQLiteStore) SaveTokens(tokens []Token) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO canaries (id, kind, value, source_ip, context, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			t.ID, string(t.Kind), t.Value, t.SourceIP, t.Context, t.CreatedAt.Format(time.RFC3339),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Close releases the database.
func (s *SQLiteStore) Close() error { return s.db.Close() }
