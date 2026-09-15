// Package store persists pipeline events.
package store

import "github.com/honeysight/honeysight/internal/core"

// Store persists events durably.
type Store interface {
	Save(e core.Event) error
	Close() error
}
