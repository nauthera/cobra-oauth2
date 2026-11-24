package oauthtest

import (
	"sync"
	"time"
)

// Clock is a fake clock whose After fires at once and moves the clock
// forward by the requested duration, so polling and backoff run without
// sleeping. It satisfies the Clock interface of package auth. Share one
// Clock between the client and the [Server] (Config.Now = clock.Now) so
// expiry, ID token and DPoP iat checks agree.
type Clock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

// DefaultStart is the time a [NewClock] starts at when given the zero time.
var DefaultStart = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// NewClock returns a clock set to start, or to [DefaultStart] when start is
// the zero time.
func NewClock(start time.Time) *Clock {
	if start.IsZero() {
		start = DefaultStart
	}
	return &Clock{now: start}
}

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After records d, advances the clock by it and returns a channel that is
// ready immediately.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	c.now = c.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

// Advance moves the clock forward by d without recording a wait.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Waits returns every duration passed to After, in order.
func (c *Clock) Waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}
