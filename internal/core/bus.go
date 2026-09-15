package core

import "log/slog"

// Subscriber consumes events from the pipeline.
type Subscriber interface {
	Name() string
	Handle(e Event)
}

// Bus is a single-consumer fan-out: the dispatcher hands every event to all
// subscribers in order. Subscribers run synchronously in the dispatcher
// goroutine, which gives deliberate backpressure: a slow store slows
// publishers instead of dropping events. M0 subscribers are all local
// (SQLite, slog, in-memory tracker) and fast.
type Bus struct {
	ch   chan Event
	subs []Subscriber
	log  *slog.Logger
}

func NewBus(buffer int, log *slog.Logger, subs ...Subscriber) *Bus {
	if buffer <= 0 {
		buffer = 1024
	}
	return &Bus{ch: make(chan Event, buffer), subs: subs, log: log}
}

// Publish sends an event to the dispatcher.
func (b *Bus) Publish(e Event) {
	b.ch <- e
}

// Start runs the dispatcher goroutine.
func (b *Bus) Start() {
	go func() {
		for e := range b.ch {
			for _, s := range b.subs {
				s.Handle(e)
			}
		}
	}()
}

// Stop closes the bus channel.
func (b *Bus) Stop() { close(b.ch) }
