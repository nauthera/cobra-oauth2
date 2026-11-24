package storage

import (
	"context"
	"errors"
	"fmt"
)

type fallbackProvider struct {
	primary, secondary Provider
}

// Fallback returns a Provider that uses primary and falls back to secondary
// when primary fails, for example a keyring that is unavailable over SSH or
// in a container, backed by [NewFile].
//
//   - Get reads primary, and secondary when primary has nothing or fails.
//   - Set writes primary; only if that fails does it write secondary. A
//     successful primary write removes any stale copy from secondary.
//   - Delete removes the key from both and reports every failure.
func Fallback(primary, secondary Provider) Provider {
	return &fallbackProvider{primary: primary, secondary: secondary}
}

// Get implements Provider.
func (p *fallbackProvider) Get(ctx context.Context, key Key) (*Token, error) {
	tok, err := p.primary.Get(ctx, key)
	if err == nil {
		return tok, nil
	}
	tok, err2 := p.secondary.Get(ctx, key)
	if err2 == nil {
		return tok, nil
	}
	if errors.Is(err, ErrNotFound) {
		return nil, err2
	}
	if errors.Is(err2, ErrNotFound) {
		return nil, err
	}
	return nil, errors.Join(err, err2)
}

// Set implements Provider.
func (p *fallbackProvider) Set(ctx context.Context, key Key, token *Token) error {
	err := p.primary.Set(ctx, key, token)
	if err == nil {
		// Best effort: a copy left in secondary from an earlier fallback
		// would otherwise shadow nothing but still sit on disk.
		_ = p.secondary.Delete(ctx, key)
		return nil
	}
	if err2 := p.secondary.Set(ctx, key, token); err2 != nil {
		return fmt.Errorf("store token: %w", errors.Join(err, err2))
	}
	return nil
}

// Delete implements Provider.
func (p *fallbackProvider) Delete(ctx context.Context, key Key) error {
	return errors.Join(p.primary.Delete(ctx, key), p.secondary.Delete(ctx, key))
}
