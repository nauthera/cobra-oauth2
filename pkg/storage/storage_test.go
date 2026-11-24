package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testKey = Key{Issuer: "https://issuer.example", ClientID: "cli"}

func sampleToken() *Token {
	return &Token{
		AccessToken:  "access-secret",
		TokenType:    "Bearer",
		RefreshToken: "refresh-secret",
		IDToken:      "id-secret",
		Expiry:       time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Scope:        "openid offline_access",
		DPoPKey:      `{"kty":"EC","crv":"P-256","d":"dpop-secret"}`,
		Extra:        map[string]any{"session_state": "x"},
	}
}

func TestKeyIDDistinguishesFields(t *testing.T) {
	t.Parallel()
	keys := []Key{
		testKey,
		{Issuer: "https://issuer.example", ClientID: "cli", Audience: "api"},
		{Issuer: "https://other.example", ClientID: "cli"},
		{Issuer: "https://issuer.example", ClientID: "cli2"},
		// The NUL separator keeps these two apart.
		{Issuer: "https://a", ClientID: "bc"},
		{Issuer: "https://ab", ClientID: "c"},
	}
	seen := map[string]Key{}
	for _, k := range keys {
		id := k.ID()
		if prev, dup := seen[id]; dup {
			t.Fatalf("ID collision between %+v and %+v", prev, k)
		}
		seen[id] = k
		if id != k.ID() {
			t.Fatalf("ID is not stable for %+v", k)
		}
		if strings.ContainsAny(id, "/\\:") {
			t.Fatalf("ID %q is not safe as a file name", id)
		}
	}
}

func TestKeyValidate(t *testing.T) {
	t.Parallel()
	if err := (Key{ClientID: "c"}).Validate(); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if err := (Key{Issuer: "i"}).Validate(); err == nil {
		t.Fatal("missing client ID accepted")
	}
	if err := testKey.Validate(); err != nil {
		t.Fatal(err)
	}
	// Without the NUL check these two keys would share an ID.
	a := Key{Issuer: "https://issuer.example\x00x", ClientID: "cli"}
	b := Key{Issuer: "https://issuer.example", ClientID: "x\x00cli"}
	if a.ID() != b.ID() {
		t.Fatal("test keys were meant to collide")
	}
	for _, k := range []Key{a, b, {Issuer: "i", ClientID: "c", Audience: "a\x00"}} {
		if err := k.Validate(); err == nil {
			t.Fatalf("key with a NUL byte accepted: %q", k)
		}
	}
}

func TestTokenExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		tok  *Token
		want bool
	}{
		{"nil", nil, true},
		{"empty access token", &Token{}, true},
		{"no expiry", &Token{AccessToken: "a"}, false},
		{"future", &Token{AccessToken: "a", Expiry: now.Add(time.Hour)}, false},
		{"within skew", &Token{AccessToken: "a", Expiry: now.Add(10 * time.Second)}, true},
		{"past", &Token{AccessToken: "a", Expiry: now.Add(-time.Second)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.tok.Expired(now, 30*time.Second); got != tc.want {
				t.Fatalf("Expired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTokenFormattingRedactsSecrets(t *testing.T) {
	t.Parallel()
	tok := sampleToken()
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("t", "token", tok)
	outputs := []string{
		fmt.Sprintf("token=%v", tok), fmt.Sprintf("token=%v", *tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok),
		fmt.Sprintf("%#v", *tok), tok.String(), logBuf.String(),
	}
	for _, out := range outputs {
		for _, secret := range []string{"access-secret", "refresh-secret", "id-secret", "dpop-secret"} {
			if strings.Contains(out, secret) {
				t.Fatalf("formatted token leaks %q: %s", secret, out)
			}
		}
	}
}

func TestTokenClone(t *testing.T) {
	t.Parallel()
	tok := sampleToken()
	c := tok.Clone()
	c.Extra["session_state"] = "changed"
	c.AccessToken = "other"
	if tok.Extra["session_state"] != "x" || tok.AccessToken != "access-secret" {
		t.Fatal("Clone shares state with the original")
	}
	if (*Token)(nil).Clone() != nil {
		t.Fatal("Clone of nil is not nil")
	}
}

// providerContract runs the behavior every Provider must have.
func providerContract(t *testing.T, p Provider) {
	t.Helper()
	ctx := context.Background()

	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store: err = %v, want ErrNotFound", err)
	}
	if err := p.Delete(ctx, testKey); err != nil {
		t.Fatalf("Delete of a missing key: %v", err)
	}
	if err := p.Set(ctx, testKey, sampleToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := p.Get(ctx, testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := sampleToken()
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken ||
		got.IDToken != want.IDToken || !got.Expiry.Equal(want.Expiry) || got.Scope != want.Scope ||
		got.TokenType != want.TokenType || got.DPoPKey != want.DPoPKey {
		t.Fatalf("round trip changed the token: %+v", got)
	}
	if got.Version != CurrentVersion || got.Issuer != testKey.Issuer || got.ClientID != testKey.ClientID {
		t.Fatalf("record not stamped with version and key: %+v", got)
	}
	if got.Extra != nil {
		t.Fatalf("Extra must not be persisted: %v", got.Extra)
	}

	other := Key{Issuer: testKey.Issuer, ClientID: testKey.ClientID, Audience: "api"}
	if _, err := p.Get(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a token for another audience was returned: %v", err)
	}

	if err := p.Delete(ctx, testKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
	}
	if err := p.Set(ctx, Key{}, sampleToken()); err == nil {
		t.Fatal("Set with an empty key accepted")
	}
}

func TestMemoryProvider(t *testing.T) {
	t.Parallel()
	providerContract(t, NewMemory())
}

func TestFileProvider(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "tokens")
	p := NewFile(dir)
	providerContract(t, p)

	ctx := context.Background()
	if err := p.Set(ctx, testKey, sampleToken()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != testKey.ID()+".json" {
		t.Fatalf("unexpected files (temporary file left behind?): %v", entries)
	}
	if runtime.GOOS == "windows" {
		return
	}
	assertMode(t, dir, 0o700)
	path := filepath.Join(dir, testKey.ID()+".json")
	assertMode(t, path, 0o600)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("world-readable token file: err = %v, want ErrInsecurePermissions", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s has mode %#o, want %#o", path, got, want)
	}
}

func TestFileProviderCorruptAndVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := NewFile(dir)
	path := filepath.Join(dir, testKey.ID()+".json")
	ctx := context.Background()

	cases := map[string]error{
		`not json`: ErrCorrupt,
		`{"iss":"https://issuer.example","client_id":"cli","access_token":"a"}`:        ErrCorrupt,
		`{"v":99,"iss":"https://issuer.example","client_id":"cli","access_token":"a"}`: ErrUnsupportedVersion,
		`{"v":1,"iss":"https://evil.example","client_id":"cli","access_token":"a"}`:    ErrNotFound,
	}
	for body, want := range cases {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Get(ctx, testKey); !errors.Is(err, want) {
			t.Errorf("record %s: err = %v, want %v", body, err, want)
		}
	}

	// A version 1 record, written before DPoP keys were stored, still reads.
	v1 := `{"v":1,"iss":"https://issuer.example","client_id":"cli","access_token":"a","refresh_token":"r"}`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := p.Get(ctx, testKey)
	if err != nil || tok.RefreshToken != "r" || tok.DPoPKey != "" {
		t.Fatalf("version 1 record: %v, %v", tok, err)
	}
}

func TestDefaultFileDir(t *testing.T) {
	t.Parallel()
	dir, err := DefaultFileDir("mycli")
	if err != nil {
		t.Skipf("no user config dir here: %v", err)
	}
	if filepath.Base(dir) != "tokens" || filepath.Base(filepath.Dir(dir)) != "mycli" {
		t.Fatalf("DefaultFileDir = %s", dir)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "../x"} {
		if _, err := DefaultFileDir(bad); err == nil {
			t.Errorf("DefaultFileDir(%q) accepted", bad)
		}
	}
}

type failingProvider struct{ err error }

func (f failingProvider) Get(context.Context, Key) (*Token, error) { return nil, f.err }
func (f failingProvider) Set(context.Context, Key, *Token) error   { return f.err }
func (f failingProvider) Delete(context.Context, Key) error        { return f.err }

func TestFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("contract", func(t *testing.T) {
		t.Parallel()
		providerContract(t, Fallback(NewMemory(), NewMemory()))
	})
	t.Run("primary unavailable", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("keyring unavailable")
		secondary := NewMemory()
		p := Fallback(failingProvider{boom}, secondary)
		if err := p.Set(ctx, testKey, sampleToken()); err != nil {
			t.Fatal(err)
		}
		if _, err := secondary.Get(ctx, testKey); err != nil {
			t.Fatalf("Set did not fall back: %v", err)
		}
		if _, err := p.Get(ctx, testKey); err != nil {
			t.Fatalf("Get did not fall back: %v", err)
		}
		if err := p.Delete(ctx, testKey); !errors.Is(err, boom) {
			t.Fatalf("Delete must report the primary failure, got %v", err)
		}
	})
	t.Run("primary write clears stale secondary", func(t *testing.T) {
		t.Parallel()
		primary, secondary := NewMemory(), NewMemory()
		if err := secondary.Set(ctx, testKey, sampleToken()); err != nil {
			t.Fatal(err)
		}
		if err := Fallback(primary, secondary).Set(ctx, testKey, sampleToken()); err != nil {
			t.Fatal(err)
		}
		if _, err := secondary.Get(ctx, testKey); !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale secondary copy kept: %v", err)
		}
	})
}
