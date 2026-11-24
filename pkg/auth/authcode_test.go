package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// browserAS is a fake server whose authorization endpoint is never called
// over HTTP: the test's "browser" (the BrowserOpener) reads the
// authorization URL and plays the server's part by redirecting to the
// loopback listener with the values redirect returns.
type browserAS struct {
	*fakeAS
	mu        sync.Mutex
	authURL   *url.URL
	challenge string
}

func (b *browserAS) auth() (*url.URL, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authURL, b.challenge
}

func newBrowserAS(t *testing.T) *browserAS {
	t.Helper()
	b := &browserAS{fakeAS: newFakeAS(t)}
	b.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		f := r.PostForm
		authURL, challenge := b.auth()
		if f.Get("grant_type") != "authorization_code" || f.Get("code") != "the-code" ||
			f.Get("redirect_uri") != authURL.Query().Get("redirect_uri") ||
			pkceChallenge(f.Get("code_verifier")) != challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		claims := b.validClaims(time.Now())
		claims["nonce"] = authURL.Query().Get("nonce")
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"access_token": "browser-access", "token_type": "Bearer", "expires_in": 600,
			"refresh_token": "browser-refresh", "id_token": b.idToken(claims),
		})
	})
	return b
}

// opener returns a BrowserOpener that follows the authorization URL with
// the redirect query that respond builds, after any extra requests.
func (b *browserAS) opener(t *testing.T, respond func(q url.Values) url.Values, before ...func(redirect string)) BrowserOpener {
	return func(ctx context.Context, raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		b.mu.Lock()
		b.authURL, b.challenge = u, q.Get("code_challenge")
		b.mu.Unlock()
		redirect := q.Get("redirect_uri")
		go func() {
			for _, f := range before {
				f(redirect)
			}
			resp, err := http.Get(redirect + "?" + respond(q).Encode())
			if err != nil {
				t.Errorf("redirect: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("callback page is cacheable")
			}
		}()
		return nil
	}
}

func okRedirect(issuer string) func(q url.Values) url.Values {
	return func(q url.Values) url.Values {
		return url.Values{"code": {"the-code"}, "state": {q.Get("state")}, "iss": {issuer}}
	}
}

func TestBrowserLogin(t *testing.T) {
	t.Parallel()
	b := newBrowserAS(t)
	b.setMetadata("authorization_response_iss_parameter_supported", true)
	var strayStatus atomic.Int64
	stray := func(redirect string) {
		// A forged or stale callback with the wrong state must not end the login.
		resp, err := http.Get(redirect + "?code=evil&state=wrong")
		if err == nil {
			strayStatus.Store(int64(resp.StatusCode))
			_ = resp.Body.Close()
		}
	}
	env := newTestEnv(t, b.fakeAS, WithBrowser(true), WithBrowserOpener(b.opener(t, okRedirect(b.URL), stray)),
		WithAuthParam("prompt", "consent"), WithAudience("https://api.example"))
	env.clock.now = time.Now()

	tok, err := env.client.BrowserLogin(context.Background())
	if err != nil {
		t.Fatalf("BrowserLogin: %v", err)
	}
	if tok.AccessToken != "browser-access" || tok.RefreshToken != "browser-refresh" || tok.IDToken == "" {
		t.Fatalf("token: %v", tok)
	}
	if got := strayStatus.Load(); got != http.StatusBadRequest {
		t.Fatalf("wrong-state callback answered %d, want 400", got)
	}
	authURL, _ := b.auth()
	q := authURL.Query()
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	switch {
	case q.Get("response_type") != "code", q.Get("client_id") != testClientID:
		t.Fatalf("authorization request: %v", q)
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43:
		t.Fatalf("PKCE must be S256: %v", q)
	case len(q.Get("state")) < 43 || len(q.Get("nonce")) < 43:
		t.Fatalf("state and nonce must carry 256 bits: %v", q)
	case redirect.Hostname() != "127.0.0.1" || redirect.Port() == "" || redirect.Path != "/callback":
		t.Fatalf("redirect URI %s", redirect)
	case q.Get("prompt") != "consent" || q.Get("audience") != "https://api.example" || q.Get("scope") != "openid offline_access":
		t.Fatalf("extra parameters: %v", q)
	}
	if strings.Contains(env.errOut.String(), "browser-access") {
		t.Fatal("token printed")
	}
}

func TestBrowserLoginRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		issParam bool
		respond  func(issuer string) func(url.Values) url.Values
		wantErr  error
	}{
		{"iss mismatch (mix-up)", false, func(string) func(url.Values) url.Values {
			return func(q url.Values) url.Values {
				return url.Values{"code": {"the-code"}, "state": {q.Get("state")}, "iss": {"https://evil.example"}}
			}
		}, ErrIssuerMismatch},
		{"iss missing although advertised", true, func(string) func(url.Values) url.Values {
			return func(q url.Values) url.Values { return url.Values{"code": {"the-code"}, "state": {q.Get("state")}} }
		}, ErrIssuerMismatch},
		{"error response", false, func(issuer string) func(url.Values) url.Values {
			return func(q url.Values) url.Values {
				return url.Values{"error": {"access_denied"}, "error_description": {"no \x1b[2J"}, "state": {q.Get("state")}, "iss": {issuer}}
			}
		}, ErrAccessDenied},
		{"no code", false, func(issuer string) func(url.Values) url.Values {
			return func(q url.Values) url.Values { return url.Values{"state": {q.Get("state")}, "iss": {issuer}} }
		}, ErrInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newBrowserAS(t)
			if tc.issParam {
				b.setMetadata("authorization_response_iss_parameter_supported", true)
			}
			env := newTestEnv(t, b.fakeAS, WithBrowser(true), WithBrowserOpener(b.opener(t, tc.respond(b.URL))))
			_, err := env.client.BrowserLogin(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if strings.ContainsRune(err.Error(), 0x1b) {
				t.Fatal("server-provided text reached the error unsanitized")
			}
			if n := len(b.requestsTo("/token")); n != 0 {
				t.Fatalf("code redeemed after a refused response (%d requests)", n)
			}
		})
	}
}

func TestBrowserLoginTimesOut(t *testing.T) {
	t.Parallel()
	b := newBrowserAS(t)
	env := newTestEnv(t, b.fakeAS, WithLoginTimeout(50*time.Millisecond))
	_, err := env.client.BrowserLogin(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
	if !strings.Contains(env.errOut.String(), "/authorize?") {
		t.Fatalf("the authorization URL was not printed for a headless session:\n%s", env.errOut.String())
	}
}

func TestBrowserLoginRequiresPAR(t *testing.T) {
	t.Parallel()
	b := newBrowserAS(t)
	b.setMetadata("require_pushed_authorization_requests", true)
	env := newTestEnv(t, b.fakeAS)
	if _, err := env.client.BrowserLogin(context.Background()); !errors.Is(err, ErrUnsupportedFlow) {
		t.Fatalf("err = %v", err)
	}
}

func TestPKCEChallenge(t *testing.T) {
	t.Parallel()
	verifier, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) != 43 || strings.ContainsAny(verifier, "+/=") {
		t.Fatalf("verifier %q is not 43 unpadded base64url characters", verifier)
	}
	sum := sha256.Sum256([]byte(verifier))
	if got, want := pkceChallenge(verifier), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("challenge = %s, want %s", got, want)
	}
}
