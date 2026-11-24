package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

const testClientID = "test-cli"

// fakeClock advances instantly: After records the duration, moves the
// clock forward by it and fires at once, so polling tests never sleep.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.waits = append(f.waits, d)
	f.now = f.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- f.now
	return ch
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fakeClock) Waits() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

// fakeAS is an httptest authorization server. Its discovery document is
// served at the OIDC location and lists every endpoint below its URL.
type fakeAS struct {
	*httptest.Server
	t   *testing.T
	mux *http.ServeMux

	mu       sync.Mutex
	metadata map[string]any
	requests []recordedRequest

	key *ecdsa.PrivateKey
}

type recordedRequest struct {
	Path   string
	Form   url.Values
	Header http.Header
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	as := &fakeAS{t: t, mux: http.NewServeMux()}
	as.Server = httptest.NewServer(http.HandlerFunc(as.serve))
	t.Cleanup(as.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	as.key = key
	as.metadata = map[string]any{
		"issuer":                                as.URL,
		"authorization_endpoint":                as.URL + "/authorize",
		"token_endpoint":                        as.URL + "/token",
		"device_authorization_endpoint":         as.URL + "/device_authorization",
		"revocation_endpoint":                   as.URL + "/revoke",
		"jwks_uri":                              as.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"ES256"},
	}
	as.mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		as.mu.Lock()
		md := as.metadata
		as.mu.Unlock()
		writeJSONResponse(w, http.StatusOK, md)
	})
	as.mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &as.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig",
		}}})
	})
	return as
}

func (as *fakeAS) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}
	as.mu.Lock()
	as.requests = append(as.requests, recordedRequest{Path: r.URL.Path, Form: r.PostForm, Header: r.Header.Clone()})
	as.mu.Unlock()
	as.mux.ServeHTTP(w, r)
}

func (as *fakeAS) setMetadata(k string, v any) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if v == nil {
		delete(as.metadata, k)
		return
	}
	as.metadata[k] = v
}

func (as *fakeAS) handle(path string, h http.HandlerFunc) { as.mux.HandleFunc(path, h) }

func (as *fakeAS) requestsTo(path string) []recordedRequest {
	as.mu.Lock()
	defer as.mu.Unlock()
	var out []recordedRequest
	for _, r := range as.requests {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// idToken signs claims with the server's key.
func (as *fakeAS) idToken(claims map[string]any) string {
	as.t.Helper()
	return signJWT(as.t, jose.ES256, jose.JSONWebKey{Key: as.key, KeyID: "k1"}, claims)
}

func (as *fakeAS) validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": as.URL, "sub": "user-1", "aud": testClientID,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "email": "user@example.com",
	}
}

func signJWT(t *testing.T, alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSONResponse(w, status, map[string]string{"error": code, "error_description": "test " + code})
}

// testEnv is a Client for a fake server with its storage, clock and captured
// output, for assertions on each.
type testEnv struct {
	client *Client
	clock  *fakeClock
	store  storage.Provider
	out    *bytes.Buffer
	errOut *bytes.Buffer
}

// newTestEnv returns a Client for as with memory storage, the fake clock,
// no browser, and its output captured.
func newTestEnv(t *testing.T, as *fakeAS, opts ...Option) *testEnv {
	t.Helper()
	env := &testEnv{clock: newFakeClock(), store: storage.NewMemory(), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	base := []Option{
		WithIssuer(as.URL),
		WithClientID(testClientID),
		WithStorage(env.store),
		WithClock(env.clock),
		WithBrowser(false),
		WithHTTPClient(as.Client()),
		WithOutput(env.out, env.errOut),
	}
	c, err := NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	env.client = c
	return env
}

func assertNoSecrets(t *testing.T, where, s string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(s, secret) {
			t.Fatalf("%s contains secret %q:\n%s", where, secret, s)
		}
	}
}
