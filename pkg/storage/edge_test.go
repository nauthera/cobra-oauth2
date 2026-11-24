package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestTokenKeyAndEmptyString(t *testing.T) {
	t.Parallel()
	tok := &Token{Issuer: "i", ClientID: "c", Audience: "a"}
	if tok.Key() != (Key{Issuer: "i", ClientID: "c", Audience: "a"}) {
		t.Fatalf("Key() = %+v", tok.Key())
	}
	if s := (Token{}).String(); !strings.Contains(s, "access_token= ") || !strings.Contains(s, "expiry=none") {
		t.Fatalf("empty token: %s", s)
	}
}

func TestSetNilToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, p := range map[string]Provider{
		"memory":  NewMemory(),
		"file":    NewFile(t.TempDir()),
		"keyring": newTestKeyring(newLimitedKeyring(2560)),
	} {
		if err := p.Set(ctx, testKey, nil); err == nil {
			t.Errorf("%s: a nil token was stored", name)
		}
	}
}

func TestWithChunkSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := newLimitedKeyring(2560)
	p := newTestKeyring(backend, WithChunkSize(minChunkSize))
	if err := p.Set(ctx, testKey, bigToken(1000)); err != nil {
		t.Fatal(err)
	}
	if backend.count() < 4 {
		t.Fatalf("a %d-byte chunk size wrote only %d entries", minChunkSize, backend.count())
	}
	if got, err := p.Get(ctx, testKey); err != nil || got.AccessToken != bigToken(1000).AccessToken {
		t.Fatalf("Get: %v", err)
	}
	// Below the minimum the option is ignored.
	if q := newTestKeyring(backend, WithChunkSize(10)); q.chunkSize != defaultChunkSize {
		t.Fatalf("chunk size %d accepted", q.chunkSize)
	}
}

func TestKeyringRecordTooLarge(t *testing.T) {
	t.Parallel()
	p := newTestKeyring(newLimitedKeyring(2560), WithChunkSize(minChunkSize))
	err := p.Set(context.Background(), testKey, bigToken(maxChunks*minChunkSize*2))
	if !errors.Is(err, keyring.ErrSetDataTooBig) {
		t.Fatalf("err = %v, want ErrSetDataTooBig", err)
	}
}

// flakyKeyring fails Get or Set for chosen accounts.
type flakyKeyring struct {
	*limitedKeyring
	failGet func(user string) bool
	failSet func(user string) bool
}

var errBackend = errors.New("backend failure")

func (f *flakyKeyring) Get(service, user string) (string, error) {
	if f.failGet != nil && f.failGet(user) {
		return "", errBackend
	}
	return f.limitedKeyring.Get(service, user)
}

func (f *flakyKeyring) Set(service, user, password string) error {
	if f.failSet != nil && f.failSet(user) {
		return errBackend
	}
	return f.limitedKeyring.Set(service, user, password)
}

func TestKeyringChunkFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	isPart := func(user string) bool { return strings.Contains(user, chunkPartSep) }

	backend := &flakyKeyring{limitedKeyring: newLimitedKeyring(2560)}
	p := newTestKeyring(backend)
	if err := p.Set(ctx, testKey, bigToken(6000)); err != nil {
		t.Fatal(err)
	}
	backend.failGet = isPart
	if _, err := p.Get(ctx, testKey); !errors.Is(err, errBackend) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("a chunk read error is a backend error, not corruption: %v", err)
	}

	writer := &flakyKeyring{limitedKeyring: newLimitedKeyring(2560), failSet: isPart}
	if err := newTestKeyring(writer).Set(ctx, testKey, bigToken(6000)); !errors.Is(err, errBackend) {
		t.Fatalf("a chunk write error must surface: %v", err)
	}
	if writer.count() != 0 {
		t.Fatal("no header may be written when a chunk failed")
	}
}

func TestKeyringCleansUpAfterCorruptHeader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := newLimitedKeyring(2560)
	p := newTestKeyring(backend)
	account := testKey.ID()
	_ = backend.Set(p.service, account, "chunks:999")
	_ = backend.Set(p.service, partAccount(account, 3), "stale")
	if err := p.Delete(ctx, testKey); err != nil {
		t.Fatal(err)
	}
	if backend.count() != 0 {
		t.Fatalf("%d entries left after deleting a corrupt record", backend.count())
	}
}

func TestFileProviderErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The directory path is taken by a file.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewFile(blocker).Set(ctx, testKey, sampleToken()); err == nil {
		t.Fatal("Set into a file path succeeded")
	}
	if _, err := NewFile(blocker).Get(ctx, testKey); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Get below a file: %v", err)
	}

	dir := t.TempDir()
	p := NewFile(dir)
	path := filepath.Join(dir, testKey.ID()+".json")

	// Oversized records are refused before they are parsed.
	big := make([]byte, maxFileSize+10)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized file: %v", err)
	}

	// A directory where the token file should be.
	_ = os.Remove(path)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, testKey); err == nil {
		t.Fatal("Delete of a non-empty directory succeeded")
	}
	if err := p.Set(ctx, testKey, sampleToken()); err == nil {
		t.Fatal("Set over a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temporary file %s left behind", e.Name())
		}
	}

	for _, bad := range []Key{{}, {Issuer: "i"}} {
		if _, err := p.Get(ctx, bad); err == nil {
			t.Fatal("Get with an invalid key")
		}
		if err := p.Delete(ctx, bad); err == nil {
			t.Fatal("Delete with an invalid key")
		}
	}
	if _, err := NewMemory().Get(ctx, Key{}); err == nil {
		t.Fatal("memory Get with an invalid key")
	}
}

func TestFileProviderReadPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	dir := t.TempDir()
	p := NewFile(dir)
	ctx := context.Background()
	if err := p.Set(ctx, testKey, sampleToken()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, testKey.ID()+".json")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := p.Get(ctx, testKey); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unreadable file: %v", err)
	}
}

func TestFallbackErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("primary down")
	bang := errors.New("secondary down")
	corrupt := failingProvider{ErrCorrupt}

	if _, err := Fallback(failingProvider{boom}, NewMemory()).Get(ctx, testKey); !errors.Is(err, boom) {
		t.Fatalf("primary failure hidden behind secondary's not-found: %v", err)
	}
	if _, err := Fallback(NewMemory(), corrupt).Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("secondary failure hidden behind primary's not-found: %v", err)
	}
	_, err := Fallback(failingProvider{boom}, failingProvider{bang}).Get(ctx, testKey)
	if !errors.Is(err, boom) || !errors.Is(err, bang) {
		t.Fatalf("both failures must be reported: %v", err)
	}
	err = Fallback(failingProvider{boom}, failingProvider{bang}).Set(ctx, testKey, sampleToken())
	if !errors.Is(err, boom) || !errors.Is(err, bang) {
		t.Fatalf("Set: %v", err)
	}
}
