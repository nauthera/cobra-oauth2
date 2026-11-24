package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

func storeToken(t *testing.T, env *testEnv, tok *storage.Token) {
	t.Helper()
	if err := env.client.save(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestTokenReturnsValidStoredToken(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "still-good", TokenType: "Bearer", Expiry: env.clock.Now().Add(time.Hour)})
	got, err := env.client.AccessToken(context.Background())
	if err != nil || got != "still-good" {
		t.Fatalf("AccessToken = %q, %v", got, err)
	}
	if n := len(as.requestsTo("/token")); n != 0 {
		t.Fatalf("a valid token was refreshed (%d requests)", n)
	}
}

func TestTokenRefreshesWithRotation(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "rt-1" {
			oauthError(w, 400, "invalid_grant")
			return
		}
		writeJSONResponse(w, 200, map[string]any{"access_token": "at-2", "token_type": "bearer", "expires_in": 600, "refresh_token": "rt-2"})
	})
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at-1", RefreshToken: "rt-1", Scope: "openid", Expiry: env.clock.Now().Add(-time.Minute)})

	tok, err := env.client.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-2" || tok.RefreshToken != "rt-2" || tok.Scope != "openid" {
		t.Fatalf("refreshed token: %v", tok)
	}
	stored, err := env.client.StoredToken(context.Background())
	if err != nil || stored.RefreshToken != "rt-2" {
		t.Fatalf("rotated refresh token not persisted: %v %v", stored, err)
	}
	// Refresh requests are authenticated like any other: a public client
	// sends its client_id.
	if as.requestsTo("/token")[0].Form.Get("client_id") != testClientID {
		t.Fatal("client_id missing from the refresh request")
	}
}

func TestRefreshKeepsRefreshTokenWithoutRotation(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, 200, map[string]any{"access_token": "at-2", "expires_in": 600})
	})
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at-1", RefreshToken: "rt-1", Expiry: env.clock.Now().Add(-time.Minute)})
	tok, err := env.client.Token(context.Background())
	if err != nil || tok.RefreshToken != "rt-1" {
		t.Fatalf("refresh token lost when the server did not rotate: %v %v", tok, err)
	}
}

func TestRefreshInvalidGrantMeansLoginRequired(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) { oauthError(w, 400, "invalid_grant") })
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at-1", RefreshToken: "rt-1", Expiry: env.clock.Now().Add(-time.Minute)})
	_, err := env.client.Token(context.Background())
	if !errors.Is(err, ErrLoginRequired) || !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err = %v", err)
	}
	if n := len(as.requestsTo("/token")); n != 1 {
		t.Fatalf("refresh retried %d times; a spent refresh token must not be reused", n)
	}
}

func TestTokenErrors(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	if _, err := env.client.Token(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("empty store: err = %v", err)
	}
	storeToken(t, env, &storage.Token{AccessToken: "at", Expiry: env.clock.Now().Add(-time.Minute)})
	if _, err := env.client.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("expired without refresh token: err = %v", err)
	}
}

func TestClientCredentials(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != testClientID || pass != "s3cret" || r.PostForm.Has("client_secret") {
			oauthError(w, 401, "invalid_client")
			return
		}
		writeJSONResponse(w, 200, map[string]any{"access_token": "cc-token", "token_type": "Bearer", "expires_in": 60})
	})
	env := newTestEnv(t, as, WithClientSecret("s3cret"), WithFlow(FlowClientCredentials))

	tok, err := env.client.Token(context.Background())
	if err != nil || tok.AccessToken != "cc-token" {
		t.Fatalf("Token with client credentials: %v %v", tok, err)
	}
	req := as.requestsTo("/token")[0]
	if req.Form.Get("grant_type") != "client_credentials" || req.Form.Has("scope") {
		t.Fatalf("no default scopes for client credentials, got form %v", req.Form)
	}
	// Expired: a new one is fetched, no refresh token needed.
	env.clock.Advance(2 * time.Minute)
	if _, err := env.client.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(as.requestsTo("/token")); n != 2 {
		t.Fatalf("token requests = %d, want 2", n)
	}
}

func TestClientAuthMethodSelection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		supported []string
		opts      []Option
		wantBasic bool
		wantPost  bool
	}{
		{"secret defaults to basic", nil, []Option{WithClientSecret("s")}, true, false},
		{"post when only post is advertised", []string{"client_secret_post", "none"}, []Option{WithClientSecret("s")}, false, true},
		{"explicit post", nil, []Option{WithClientSecret("s"), WithAuthMethod(ClientAuthSecretPost)}, false, true},
		{"public client", nil, nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			as := newFakeAS(t)
			if tc.supported != nil {
				as.setMetadata("token_endpoint_auth_methods_supported", tc.supported)
			}
			as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(w, 200, map[string]any{"access_token": "a"})
			})
			env := newTestEnv(t, as, tc.opts...)
			if _, err := env.client.ClientCredentials(context.Background()); err != nil {
				t.Fatal(err)
			}
			req := as.requestsTo("/token")[0]
			hasBasic := strings.HasPrefix(req.Header.Get("Authorization"), "Basic ")
			hasPost := req.Form.Has("client_secret")
			if hasBasic != tc.wantBasic || hasPost != tc.wantPost {
				t.Fatalf("basic=%v post=%v, want %v %v", hasBasic, hasPost, tc.wantBasic, tc.wantPost)
			}
			if hasBasic && hasPost {
				t.Fatal("credentials sent twice")
			}
			if !hasBasic && req.Form.Get("client_id") != testClientID {
				t.Fatal("client_id missing from the body")
			}
		})
	}
}

func TestTransport(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, 200, map[string]any{"access_token": "fresh", "expires_in": 600, "refresh_token": "rt-2"})
	})
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="revoked"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(body)
	}))
	defer api.Close()

	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "revoked", RefreshToken: "rt-1", Expiry: env.clock.Now().Add(time.Hour)})
	hc := &http.Client{Transport: env.client.Transport(api.Client().Transport)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL, strings.NewReader("payload"))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "payload" || calls.Load() != 2 {
		t.Fatalf("status %d body %q calls %d: want a refresh and one replay", resp.StatusCode, body, calls.Load())
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("the transport modified the caller's request")
	}
}

func TestLogoutRevokesThenDeletes(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at", RefreshToken: "rt"})
	if err := env.client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqs := as.requestsTo("/revoke")
	if len(reqs) != 2 || reqs[0].Form.Get("token_type_hint") != "refresh_token" || reqs[0].Form.Get("token") != "rt" ||
		reqs[1].Form.Get("token_type_hint") != "access_token" || reqs[1].Form.Get("client_id") != testClientID {
		t.Fatalf("revocation requests: %+v", reqs)
	}
	if _, err := env.client.StoredToken(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal("token still stored after logout")
	}
	if err := env.client.Logout(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("second logout: %v", err)
	}
}

func TestLogoutRetriesUnavailableAndStillDeletes(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	var n atomic.Int64
	as.handle("/revoke", func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
	})
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at", RefreshToken: "rt"})
	err := env.client.Logout(context.Background())
	if !errors.Is(err, ErrRevocationFailed) {
		t.Fatalf("err = %v, want ErrRevocationFailed", err)
	}
	if n.Load() != 2*revokeAttempts {
		t.Fatalf("revocation attempts = %d, want %d", n.Load(), 2*revokeAttempts)
	}
	if _, err := env.client.StoredToken(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal("local token kept after failed revocation")
	}
}

func TestLogoutWithoutRevocationEndpoint(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("revocation_endpoint", nil)
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at"})
	if err := env.client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := env.client.Revoke(context.Background(), "at", "access_token"); !errors.Is(err, ErrRevocationUnsupported) {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestStatusUsesIDTokenWithoutSecrets(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	idt := as.idToken(as.validClaims(env.clock.Now()))
	storeToken(t, env, &storage.Token{AccessToken: "at-secret", RefreshToken: "rt-secret", IDToken: idt, TokenType: "Bearer", Expiry: env.clock.Now().Add(time.Hour)})
	st, err := env.client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject != "user-1" || st.Email != "user@example.com" || !st.HasRefreshToken || st.Expired {
		t.Fatalf("status: %+v", st)
	}
}

func TestClientStringRedactsSecret(t *testing.T) {
	t.Parallel()
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithClientSecret("very-secret"))
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "Client.String", c.String()+fmt.Sprintf("%v %+v", c, c), "very-secret")
}

func TestNewClientValidation(t *testing.T) {
	t.Parallel()
	base := []Option{WithIssuer("https://as.example"), WithClientID("c")}
	cases := map[string][]Option{
		"no client id":                 {WithIssuer("https://as.example")},
		"no issuer or endpoint":        {WithClientID("c")},
		"http issuer":                  {WithIssuer("http://as.example"), WithClientID("c")},
		"issuer with query":            {WithIssuer("https://as.example?x"), WithClientID("c")},
		"unknown flow":                 append(base, WithFlow("password")),
		"client credentials no secret": append(base, WithFlow(FlowClientCredentials)),
		"basic without secret":         append(base, WithAuthMethod(ClientAuthSecretBasic)),
		"non-loopback redirect":        append(base, WithRedirectHost("example.com")),
		"bad redirect path":            append(base, WithRedirectPath("callback")),
		"bad scope":                    append(base, WithScopes("a b")),
		"insecure endpoint":            append(base, WithTokenEndpoint("http://as.example/token")),
		"preset error":                 {EntraID(""), WithClientID("c")},
	}
	for name, opts := range cases {
		if _, err := NewClient(opts...); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := NewClient(append(base, WithInsecureHTTP(), WithTokenEndpoint("http://as.example/token"))...); err != nil {
		t.Errorf("WithInsecureHTTP: %v", err)
	}
}
