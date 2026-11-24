package storage

import (
	"context"
	"sync"
)

type memoryProvider struct {
	mu     sync.Mutex
	tokens map[Key]*Token
}

// NewMemory returns a Provider that keeps token sets in process memory. They
// are gone when the process exits, which suits tests and one-shot CI jobs.
func NewMemory() Provider {
	return &memoryProvider{tokens: make(map[Key]*Token)}
}

// Get implements Provider.
func (m *memoryProvider) Get(_ context.Context, key Key) (*Token, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[key]
	if !ok {
		return nil, ErrNotFound
	}
	return tok.Clone(), nil
}

// Set implements Provider.
func (m *memoryProvider) Set(_ context.Context, key Key, token *Token) error {
	if err := key.Validate(); err != nil {
		return err
	}
	// Round-trip through the record format so memory behaves like the
	// persistent providers (version stamped, key copied in, Extra dropped).
	data, err := encodeRecord(key, token)
	if err != nil {
		return err
	}
	rec, err := decodeRecord(key, data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[key] = rec
	return nil
}

// Delete implements Provider.
func (m *memoryProvider) Delete(_ context.Context, key Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, key)
	return nil
}
