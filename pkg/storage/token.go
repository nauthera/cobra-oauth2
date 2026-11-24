// Package storage persists OAuth 2.0 token sets for a command-line client.
//
// A [Provider] stores one [Token] per [Key]. The key binds a token set to the
// authorization server (issuer), the client and the audience it was issued
// for, so two tools, two environments or two tenants that happen to share a
// client ID never read or overwrite each other's tokens.
//
// Three providers ship with the package: [NewKeyring] (the operating
// system's credential store, the default), [NewFile] (an opt-in JSON file per
// token set with owner-only permissions) and [NewMemory] (tests and
// short-lived processes). [Fallback] combines two of them.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// CurrentVersion is the version of the [Token] record format this package
// writes. Readers accept every version up to it and refuse newer records
// rather than guessing at their meaning.
//
// Version 2 added [Token.DPoPKey]. A version 1 record reads as a token set
// without a DPoP key.
const CurrentVersion = 2

// Sentinel errors returned by providers. Wrap-aware: compare with errors.Is.
var (
	// ErrNotFound means no token set is stored for the key.
	ErrNotFound = errors.New("no stored token")
	// ErrCorrupt means a stored record exists but cannot be decoded.
	ErrCorrupt = errors.New("stored token record is corrupt")
	// ErrUnsupportedVersion means a stored record was written by a newer
	// version of this package.
	ErrUnsupportedVersion = errors.New("stored token record has an unsupported version")
	// ErrInsecurePermissions means a token file is readable or writable by
	// users other than its owner.
	ErrInsecurePermissions = errors.New("token file permissions are too open")
)

// Key identifies one stored token set.
//
// Issuer and ClientID are required. Audience is optional and distinguishes
// token sets the same client holds for different APIs (an RFC 8707 resource,
// an Auth0 audience) or different profiles of the same application.
type Key struct {
	Issuer   string
	ClientID string
	Audience string
}

// ID returns a stable, opaque identifier for the key, suitable as a keyring
// account name or a file name. It is a hash, so it reveals nothing about the
// issuer or client and is the same on every platform.
func (k Key) ID() string {
	h := sha256.New()
	// NUL separators: Validate refuses a field containing one, so the
	// encoding is injective for every key a provider accepts.
	_, _ = h.Write([]byte(k.Issuer))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.ClientID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.Audience))
	return "oauth2-" + hex.EncodeToString(h.Sum(nil))[:40]
}

// Validate reports whether the key has the fields every provider needs. A
// field may not contain a NUL byte, which [Key.ID] uses as its separator:
// otherwise two different keys could share an ID and overwrite each
// other's token set.
func (k Key) Validate() error {
	if k.Issuer == "" {
		return errors.New("storage key: issuer is required")
	}
	if k.ClientID == "" {
		return errors.New("storage key: client ID is required")
	}
	if strings.ContainsRune(k.Issuer+k.ClientID+k.Audience, 0) {
		return errors.New("storage key: a field contains a NUL byte")
	}
	return nil
}

// Token is a persisted token set.
//
// The Issuer, ClientID and Audience fields repeat the [Key] the record was
// stored under, so a reader can check that a record really belongs to the
// server it is about to present the access token to.
//
// Token implements fmt.Stringer, fmt.GoStringer and slog.LogValuer with the
// secrets redacted, so logging or printing one with %v or %+v is safe.
type Token struct {
	// Version is the record format version, [CurrentVersion] when written by
	// this package.
	Version int `json:"v"`

	Issuer   string `json:"iss"`
	ClientID string `json:"client_id"`
	Audience string `json:"aud,omitempty"`

	AccessToken string `json:"access_token"`
	// TokenType is the canonical token type: "Bearer" or "DPoP".
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	// Expiry is when the access token expires. The zero value means the
	// server did not say (some providers issue non-expiring tokens).
	Expiry time.Time `json:"expiry,omitzero"`
	// Scope is the space-separated scope the server granted.
	Scope string `json:"scope,omitempty"`
	// DPoPKey is the private key, as a JSON Web Key, that the token set is
	// bound to with DPoP (RFC 9449). A DPoP-bound refresh token is useless
	// without it, so it is stored with the tokens. Empty for Bearer tokens.
	DPoPKey string `json:"dpop_key,omitempty"`

	// Extra holds token-response members this package does not model, such
	// as refresh_expires_in or session_state. It is not persisted.
	Extra map[string]any `json:"-"`
}

// Expired reports whether the access token is expired, or will be within
// skew, at now. A token without an expiry never expires by this test.
func (t *Token) Expired(now time.Time, skew time.Duration) bool {
	if t == nil || t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return !now.Add(skew).Before(t.Expiry)
}

// Key returns the key the record names.
func (t *Token) Key() Key {
	return Key{Issuer: t.Issuer, ClientID: t.ClientID, Audience: t.Audience}
}

// Clone returns a deep copy of t.
func (t *Token) Clone() *Token {
	if t == nil {
		return nil
	}
	c := *t
	if t.Extra != nil {
		c.Extra = make(map[string]any, len(t.Extra))
		for k, v := range t.Extra {
			c.Extra[k] = v
		}
	}
	return &c
}

func redacted(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// String returns a description of the token set with every secret redacted.
// It has a value receiver so that formatting a Token value, not only a
// pointer, redacts as well.
func (t Token) String() string {
	exp := "none"
	if !t.Expiry.IsZero() {
		exp = t.Expiry.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("Token{iss=%q client_id=%q type=%q scope=%q expiry=%s access_token=%s refresh_token=%s id_token=%s dpop_key=%s}",
		t.Issuer, t.ClientID, t.TokenType, t.Scope, exp,
		redacted(t.AccessToken), redacted(t.RefreshToken), redacted(t.IDToken), redacted(t.DPoPKey))
}

// GoString implements fmt.GoStringer so %#v redacts too.
func (t Token) GoString() string { return t.String() }

// LogValue implements slog.LogValuer with every secret redacted.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("iss", t.Issuer),
		slog.String("client_id", t.ClientID),
		slog.String("token_type", t.TokenType),
		slog.String("scope", t.Scope),
		slog.Time("expiry", t.Expiry),
		slog.Bool("has_refresh_token", t.RefreshToken != ""),
		slog.Bool("has_id_token", t.IDToken != ""),
		slog.Bool("has_dpop_key", t.DPoPKey != ""),
	)
}
