package auth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// env is a client under test wired to an oauthtest server: a shared fake
// clock, memory storage, no real browser and captured output.
type env struct {
	as     *oauthtest.Server
	clock  *oauthtest.Clock
	store  storage.Provider
	out    *syncBuffer
	errOut *syncBuffer
	client *auth.Client
	preset []auth.Option
	base   []auth.Option
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes a browser
// flow's goroutines may make.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newEnv starts a server with cfg (its clock replaced by the env's) and
// builds a client for it from preset (a provider preset and the client ID,
// say), the env's options,
// which point the client at the server and so override the preset's
// issuer, and then opts.
func newEnv(t *testing.T, cfg oauthtest.Config, preset []auth.Option, opts ...auth.Option) *env {
	t.Helper()
	e := &env{
		clock: oauthtest.NewClock(oauthtest.DefaultStart), store: storage.NewMemory(),
		out: &syncBuffer{}, errOut: &syncBuffer{}, preset: preset,
	}
	cfg.Now = e.clock.Now
	e.as = oauthtest.New(t, cfg)
	e.base = []auth.Option{
		auth.WithIssuer(e.as.Issuer()),
		auth.WithHTTPClient(e.as.Client()),
		auth.WithStorage(e.store),
		auth.WithClock(e.clock),
		auth.WithBrowser(false),
		auth.WithOutput(e.out, e.errOut),
	}
	// Without a preset or options the test builds its clients itself,
	// typically from a preset that needs the server's URL.
	if preset != nil || len(opts) > 0 {
		e.client = e.newClient(t, opts...)
	}
	return e
}

// newClient builds another client on the same server, clock and store:
// what a second run of the CLI would be.
func (e *env) newClient(t *testing.T, opts ...auth.Option) *auth.Client {
	t.Helper()
	all := append(append(append([]auth.Option(nil), e.preset...), e.base...), opts...)
	c, err := auth.NewClient(all...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func mustLogin(t *testing.T, c *auth.Client) *storage.Token {
	t.Helper()
	tok, err := c.Login(t.Context())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return tok
}

func wantErr(t *testing.T, err error, targets ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want %v", targets)
	}
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Fatalf("err = %v, want it to match %v", err, target)
		}
	}
}

func oauthErr(t *testing.T, err error) *auth.OAuthError {
	t.Helper()
	var oe *auth.OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v (%T), want an *auth.OAuthError", err, err)
	}
	return oe
}

func assertNoSecret(t *testing.T, where, s string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(s, secret) {
			t.Fatalf("%s contains the secret %q:\n%s", where, secret, s)
		}
	}
}

func get(t *testing.T, hc *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.WithoutCancel(t.Context()), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// foreignDPoPKey returns a private JWK, as storage.Token.DPoPKey holds it,
// that the server has never seen.
func foreignDPoPKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&jose.JSONWebKey{Key: k, Algorithm: string(jose.ES256), Use: "sig"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
