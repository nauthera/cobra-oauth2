package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// limitedKeyring is an in-memory keyring that refuses values over limit
// bytes, like Windows Credential Manager (2560 bytes).
type limitedKeyring struct {
	mu      sync.Mutex
	limit   int
	entries map[string]string
	sets    int
}

func newLimitedKeyring(limit int) *limitedKeyring {
	return &limitedKeyring{limit: limit, entries: map[string]string{}}
}

func (k *limitedKeyring) Set(service, user, password string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets++
	if len(password) > k.limit {
		return keyring.ErrSetDataTooBig
	}
	k.entries[service+"\x00"+user] = password
	return nil
}

func (k *limitedKeyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.entries[service+"\x00"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (k *limitedKeyring) Delete(service, user string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.entries[service+"\x00"+user]; !ok {
		return keyring.ErrNotFound
	}
	delete(k.entries, service+"\x00"+user)
	return nil
}

func (k *limitedKeyring) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}

func newTestKeyring(backend keyringBackend, opts ...KeyringOption) *keyringProvider {
	p := NewKeyring("com.example.test", opts...).(*keyringProvider)
	p.backend = backend
	return p
}

func bigToken(n int) *Token {
	tok := sampleToken()
	// A realistic Entra/Keycloak-sized JWT with group claims.
	tok.AccessToken = strings.Repeat("a", n)
	tok.IDToken = strings.Repeat("é", n/4) // multi-byte runes must not be split
	return tok
}

func TestKeyringContract(t *testing.T) {
	t.Parallel()
	providerContract(t, newTestKeyring(newLimitedKeyring(2560)))
}

func TestKeyringChunksLargeRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := newLimitedKeyring(2560)
	p := newTestKeyring(backend)

	if err := p.Set(ctx, testKey, bigToken(9000)); err != nil {
		t.Fatalf("Set of a large token: %v", err)
	}
	if backend.count() < 2 {
		t.Fatalf("large record was not chunked: %d entries", backend.count())
	}
	got, err := p.Get(ctx, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != bigToken(9000).AccessToken || got.IDToken != bigToken(9000).IDToken {
		t.Fatal("chunked record did not round-trip")
	}

	// Shrinking the record removes the chunks it no longer needs.
	if err := p.Set(ctx, testKey, sampleToken()); err != nil {
		t.Fatal(err)
	}
	if backend.count() != 1 {
		t.Fatalf("stale chunks left behind: %d entries", backend.count())
	}

	if err := p.Set(ctx, testKey, bigToken(9000)); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, testKey); err != nil {
		t.Fatal(err)
	}
	if backend.count() != 0 {
		t.Fatalf("Delete left %d entries", backend.count())
	}
}

func TestKeyringShrinksChunkOnTooBig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Smaller than the default chunk size: the provider must halve until
	// the writes fit.
	backend := newLimitedKeyring(700)
	p := newTestKeyring(backend)
	if err := p.Set(ctx, testKey, bigToken(3000)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := p.Get(ctx, testKey); err != nil {
		t.Fatal(err)
	}
}

func TestKeyringCorruptChunks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := newLimitedKeyring(2560)
	p := newTestKeyring(backend)
	account := testKey.ID()

	_ = backend.Set(p.service, account, "chunks:abc")
	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad header: err = %v, want ErrCorrupt", err)
	}
	_ = backend.Set(p.service, account, "chunks:2")
	_ = backend.Set(p.service, partAccount(account, 1), "{")
	if _, err := p.Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing chunk: err = %v, want ErrCorrupt", err)
	}
}

func TestKeyringRequiresService(t *testing.T) {
	t.Parallel()
	p := NewKeyring("")
	if err := p.Set(context.Background(), testKey, sampleToken()); err == nil {
		t.Fatal("empty service name accepted")
	}
}

func TestKeyringBackendErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("dbus not available")
	p := newTestKeyring(failingBackend{boom})
	ctx := context.Background()
	if _, err := p.Get(ctx, testKey); !errors.Is(err, boom) {
		t.Fatalf("Get: %v", err)
	}
	if err := p.Set(ctx, testKey, sampleToken()); !errors.Is(err, boom) {
		t.Fatalf("Set: %v", err)
	}
	if err := p.Delete(ctx, testKey); !errors.Is(err, boom) {
		t.Fatalf("Delete: %v", err)
	}
}

type failingBackend struct{ err error }

func (f failingBackend) Set(string, string, string) error   { return f.err }
func (f failingBackend) Get(string, string) (string, error) { return "", f.err }
func (f failingBackend) Delete(string, string) error        { return f.err }

// TestSystemKeyringMock goes through go-keyring itself, with its mock
// backend, so the adapter is exercised too.
func TestSystemKeyringMock(t *testing.T) {
	keyring.MockInit()
	providerContract(t, NewKeyring("com.example.test"))
}

func TestSplitUTF8(t *testing.T) {
	t.Parallel()
	s := strings.Repeat("aé€😀", 50)
	for _, size := range []int{1, 3, 7, 64} {
		parts := splitUTF8(s, size)
		if strings.Join(parts, "") != s {
			t.Fatalf("size %d: parts do not join back", size)
		}
		if size >= 4 {
			for _, p := range parts {
				if len(p) > size {
					t.Fatalf("size %d: part %q too long", size, p)
				}
				if strings.ToValidUTF8(p, "�") != p {
					t.Fatalf("size %d: part %q splits a rune", size, p)
				}
			}
		}
	}
}
