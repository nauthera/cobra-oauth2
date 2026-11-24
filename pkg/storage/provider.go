package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Provider stores token sets.
//
// Implementations must be safe for concurrent use. Get returns an error
// wrapping [ErrNotFound] when nothing is stored for the key. Delete of a key
// that holds nothing returns nil, so logging out twice is not an error.
type Provider interface {
	Get(ctx context.Context, key Key) (*Token, error)
	Set(ctx context.Context, key Key, token *Token) error
	Delete(ctx context.Context, key Key) error
}

// encodeRecord serializes a token set in the versioned record format, with
// the key copied into it.
func encodeRecord(key Key, token *Token) ([]byte, error) {
	if token == nil {
		return nil, errors.New("encode token record: token is nil")
	}
	rec := token.Clone()
	rec.Version = CurrentVersion
	rec.Issuer, rec.ClientID, rec.Audience = key.Issuer, key.ClientID, key.Audience
	b, err := json.Marshal(rec) //nolint:gosec // G117: this is the token record; persisting the secrets is its purpose
	if err != nil {
		return nil, fmt.Errorf("encode token record: %w", err)
	}
	return b, nil
}

// decodeRecord parses a record and checks that it was stored for key.
func decodeRecord(key Key, data []byte) (*Token, error) {
	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if tok.Version < 1 {
		return nil, fmt.Errorf("%w: missing version", ErrCorrupt)
	}
	if tok.Version > CurrentVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, tok.Version)
	}
	// The record must belong to the key it was found under. A mismatch means
	// the entry was written by something else; treat it as absent rather
	// than handing a foreign token to the caller.
	if tok.Issuer != key.Issuer || tok.ClientID != key.ClientID || tok.Audience != key.Audience {
		return nil, fmt.Errorf("%w: record belongs to a different issuer or client", ErrNotFound)
	}
	return &tok, nil
}
