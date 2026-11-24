package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// rotatingServer issues rt-<n+1> for rt-<n> once, and answers a reused
// refresh token with invalid_grant, as nauthera, Auth0, Okta and Entra do.
func rotatingServer(t *testing.T, extra func(n int64) map[string]any) (*fakeAS, *atomic.Int64) {
	t.Helper()
	as := newFakeAS(t)
	var (
		mu    sync.Mutex
		spent = map[string]bool{}
		n     atomic.Int64
	)
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		rt := r.PostForm.Get("refresh_token")
		mu.Lock()
		reused := spent[rt]
		spent[rt] = true
		mu.Unlock()
		if reused {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		i := n.Add(1)
		body := map[string]any{"access_token": "at-rotated", "token_type": "Bearer", "expires_in": 600, "refresh_token": "rt-rotated"}
		for k, v := range extra(i) {
			body[k] = v
		}
		writeJSONResponse(w, http.StatusOK, body)
	})
	return as, &n
}

func expiredSet(env *testEnv, idToken string) *storage.Token {
	return &storage.Token{
		AccessToken: "at-1", TokenType: TokenTypeBearer, RefreshToken: "rt-1", IDToken: idToken,
		Expiry: env.clock.Now().Add(-time.Minute),
	}
}

func storedSet(t *testing.T, env *testEnv) *storage.Token {
	t.Helper()
	tok, err := env.store.Get(context.Background(), env.client.StorageKey())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The server rotated the refresh token, but the ID token in the same
// response could not be checked because the JWKS was unavailable. The
// rotated refresh token must be stored: the spent one would trip reuse
// detection on the next run and revoke the grant.
func TestRefreshKeepsRotatedTokenWhenJWKSIsDown(t *testing.T) {
	t.Parallel()
	var as *fakeAS
	var env *testEnv
	as, _ = rotatingServer(t, func(int64) map[string]any {
		return map[string]any{"id_token": as.idToken(as.validClaims(env.clock.Now()))}
	})
	as.setMetadata("jwks_uri", as.URL+"/jwks-down")
	as.handle("/jwks-down", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	env = newTestEnv(t, as)
	prevID := as.idToken(as.validClaims(env.clock.Now()))
	storeToken(t, env, expiredSet(env, prevID))

	tok, err := env.client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v (an unreachable JWKS must not fail the refresh)", err)
	}
	if tok.AccessToken != "at-rotated" {
		t.Fatalf("access token %q", tok.AccessToken)
	}
	stored := storedSet(t, env)
	if stored.RefreshToken != "rt-rotated" || stored.IDToken != prevID {
		t.Fatalf("stored refresh token %q, ID token kept: %v", stored.RefreshToken, stored.IDToken == prevID)
	}
}

// An ID token that fails validation is an error, but the token set it came
// with is stored anyway, without that ID token.
func TestRefreshKeepsRotatedTokenWhenIDTokenIsInvalid(t *testing.T) {
	t.Parallel()
	var as *fakeAS
	var env *testEnv
	as, _ = rotatingServer(t, func(int64) map[string]any {
		claims := as.validClaims(env.clock.Now())
		claims["sub"] = "someone-else"
		return map[string]any{"id_token": as.idToken(claims)}
	})
	env = newTestEnv(t, as)
	storeToken(t, env, expiredSet(env, as.idToken(as.validClaims(env.clock.Now()))))

	_, err := env.client.Token(context.Background())
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("Token: %v, want ErrInvalidIDToken", err)
	}
	stored := storedSet(t, env)
	if stored.RefreshToken != "rt-rotated" || stored.IDToken != "" {
		t.Fatalf("stored refresh token %q, ID token %q", stored.RefreshToken, stored.IDToken)
	}
	// The public method hands the caller the token set to store as well.
	next, err := env.client.Refresh(context.Background(), &storage.Token{RefreshToken: "rt-fresh", IDToken: stored.IDToken})
	if err != nil || next == nil {
		t.Fatalf("Refresh without a previous ID token: %v %v", next, err)
	}
}

// A DPoP token issued to a request without a proof is unusable, but the
// refresh token that came with it is not lost.
func TestRefreshKeepsRotatedTokenWhenDPoPBindingFails(t *testing.T) {
	t.Parallel()
	as, _ := rotatingServer(t, func(int64) map[string]any { return map[string]any{"token_type": "DPoP"} })
	env := newTestEnv(t, as)
	storeToken(t, env, expiredSet(env, ""))

	if _, err := env.client.Token(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Token: %v", err)
	}
	stored := storedSet(t, env)
	if stored.RefreshToken != "rt-rotated" || stored.AccessToken != "" {
		t.Fatalf("stored %v: want the rotated refresh token and no access token", stored)
	}
}

// Two runs of the CLI find the same expired token at the same moment. With
// the storage lock, only one of them redeems the refresh token; the other
// re-reads storage once it holds the lock and uses the new token set.
func TestParallelProcessesRefreshOnce(t *testing.T) {
	t.Parallel()
	as, refreshes := rotatingServer(t, func(int64) map[string]any { return nil })
	dir := t.TempDir()
	clock := newFakeClock()
	newRun := func() *Client {
		c, err := NewClient(
			WithIssuer(as.URL), WithClientID(testClientID), WithHTTPClient(as.Client()),
			WithStorage(storage.NewFile(dir)), WithClock(clock), WithBrowser(false),
		)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := newRun()
	if err := first.save(context.Background(), &storage.Token{
		AccessToken: "at-1", RefreshToken: "rt-1", Expiry: clock.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	const runs = 8
	var wg sync.WaitGroup
	errs := make([]error, runs)
	for i := range runs {
		wg.Go(func() {
			// A fresh client per goroutine: separate caches and separate
			// in-process mutexes, like separate processes. Only the file
			// lock is shared.
			tok, err := newRun().Token(context.Background())
			if err == nil && tok.AccessToken != "at-rotated" {
				err = errors.New("unexpected access token " + tok.AccessToken)
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("run %d: %v", i, err)
		}
	}
	if n := refreshes.Load(); n != 1 {
		t.Fatalf("%d refreshes, want exactly 1", n)
	}
	if reqs := as.requestsTo("/token"); len(reqs) != 1 {
		t.Fatalf("%d token requests: the refresh token was presented more than once", len(reqs))
	}
}

// countingStore counts reads.
type countingStore struct {
	storage.Provider
	gets atomic.Int64
}

func (s *countingStore) Get(ctx context.Context, k storage.Key) (*storage.Token, error) {
	s.gets.Add(1)
	return s.Provider.Get(ctx, k)
}

// A valid token set is kept in memory: requests through the transport do
// not read the keyring (a process spawn per read on macOS) each time.
func TestTokenIsCachedWhileValid(t *testing.T) {
	t.Parallel()
	as, _ := rotatingServer(t, func(int64) map[string]any { return nil })
	store := &countingStore{Provider: storage.NewMemory()}
	env := newTestEnv(t, as, WithStorage(store))
	if err := store.Set(context.Background(), env.client.StorageKey(), &storage.Token{
		AccessToken: "at-1", RefreshToken: "rt-1", Expiry: env.clock.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		tok, err := env.client.Token(context.Background())
		if err != nil || tok.AccessToken != "at-1" {
			t.Fatalf("Token: %v %v", tok, err)
		}
		tok.AccessToken = "mutated by the caller"
	}
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("%d storage reads for 5 calls, want 1", n)
	}

	// Once it expires, storage is read again (another process may have
	// renewed it) before refreshing.
	env.clock.Advance(2 * time.Hour)
	tok, err := env.client.Token(context.Background())
	if err != nil || tok.AccessToken != "at-rotated" {
		t.Fatalf("after expiry: %v %v", tok, err)
	}
	if n := store.gets.Load(); n < 2 {
		t.Fatalf("storage not read again after expiry (%d reads)", n)
	}

	// Logout forgets the cached set.
	if err := env.client.Logout(context.Background()); err != nil && !errors.Is(err, ErrRevocationFailed) {
		t.Fatal(err)
	}
	if _, err := env.client.Token(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after logout: %v", err)
	}
}
