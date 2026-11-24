package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// headerRecorder is a server that records the Authorization header of
// every request it receives.
type headerRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newHeaderRecorder(t *testing.T, h http.HandlerFunc) *headerRecorder {
	t.Helper()
	r := &headerRecorder{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Header.Get("Authorization")+"|"+req.Header.Get("DPoP"))
		r.mu.Unlock()
		if h != nil {
			h(w, req)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *headerRecorder) headers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func transportEnv(t *testing.T, opts ...Option) *testEnv {
	t.Helper()
	env := newTestEnv(t, newFakeAS(t), opts...)
	storeToken(t, env, &storage.Token{AccessToken: "SECRET-AT", TokenType: TokenTypeBearer, Expiry: env.clock.Now().Add(time.Hour)})
	return env
}

func get(t *testing.T, hc *http.Client, u string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

// A redirect to another origin is followed without the access token: an
// open redirect on the API or a redirect to a signed storage URL must not
// hand the bearer token to a third party.
func TestTransportDropsTokenOnCrossOriginRedirect(t *testing.T) {
	t.Parallel()
	thirdParty := newHeaderRecorder(t, nil)
	api := newHeaderRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, thirdParty.URL+"/stolen", http.StatusFound)
		case "/here":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		default:
			_, _ = io.WriteString(w, "api")
		}
	})
	env := transportEnv(t)
	hc := &http.Client{Transport: env.client.Transport(nil)}

	resp, err := get(t, hc, api.URL+"/away")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := thirdParty.headers(); len(got) != 1 || got[0] != "|" {
		t.Fatalf("the redirect target received %q, want no Authorization or DPoP header", got)
	}
	if got := api.headers(); len(got) != 1 || got[0] != "Bearer SECRET-AT|" {
		t.Fatalf("the API received %q", got)
	}

	// A same-origin redirect keeps the token.
	if _, err := get(t, hc, api.URL+"/here"); err != nil {
		t.Fatal(err)
	}
	if got := api.headers(); len(got) != 3 || got[2] != "Bearer SECRET-AT|" {
		t.Fatalf("same-origin redirect: %q", got)
	}

	// Calling the other origin directly is an error, not a silent
	// unauthenticated request.
	_, err = get(t, hc, thirdParty.URL+"/direct")
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("direct request to another origin: %v", err)
	}
	if n := len(thirdParty.headers()); n != 1 {
		t.Fatalf("the refused request was sent (%d requests)", n)
	}
}

// roundTripFunc records requests without sending them anywhere.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okResponse(r *http.Request) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}
}

func TestTransportAllowedOrigins(t *testing.T) {
	t.Parallel()
	var (
		mu   sync.Mutex
		sent []string
	)
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		sent = append(sent, r.URL.String()+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		return okResponse(r), nil
	})
	do := func(rt http.RoundTripper, u string) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}

	env := transportEnv(t)
	rt := env.client.Transport(base, WithAllowedOrigins("https://api.example.com/v1", "https://files.example.com:8443"))
	for _, u := range []string{"https://API.example.com:443/x", "https://files.example.com:8443/y"} {
		if err := do(rt, u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"https://evil.example/x", "https://files.example.com/y", "http://api.example.com/x"} {
		if err := do(rt, u); err == nil {
			t.Errorf("%s was authorized", u)
		}
	}
	// Plain http to a remote host is refused before anything is sent.
	if err := do(env.client.Transport(base, WithAllowedOrigins("http://api.example.com")), "http://api.example.com/x"); !errors.Is(err, ErrInsecureEndpoint) {
		t.Errorf("plain http: %v", err)
	}
	if err := do(env.client.Transport(base, WithAllowedOrigins("ftp://x")), "https://api.example.com/"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("an invalid origin: %v", err)
	}
	mu.Lock()
	if len(sent) != 2 {
		t.Errorf("sent %q, want only the two allowed requests", sent)
	}
	mu.Unlock()

	// The http(s) resource indicators are the default origins.
	res := transportEnv(t, WithResource("https://api.example.com/", "urn:example:other"))
	rt = res.client.Transport(base)
	if err := do(rt, "https://api.example.com/z"); err != nil {
		t.Errorf("resource origin: %v", err)
	}
	if err := do(rt, "https://other.example/z"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("another origin with resources set: %v", err)
	}

	// Without either, the first request pins the origin.
	rt = env.client.Transport(base)
	if err := do(rt, "https://first.example/a"); err != nil {
		t.Fatal(err)
	}
	if err := do(rt, "https://second.example/a"); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("second origin: %v", err)
	}
}

func TestCanonicalOrigin(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"https://Example.COM":      "https://example.com:443",
		"https://example.com:443/": "https://example.com:443",
		"http://127.0.0.1/x?y=1":   "http://127.0.0.1:80",
		"https://[::1]:8443/":      "https://[::1]:8443",
		"ftp://example.com":        "",
		"https:///nohost":          "",
	} {
		got, err := parseOrigin(raw)
		if want == "" {
			if err == nil {
				t.Errorf("parseOrigin(%q) = %q, want an error", raw, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("parseOrigin(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
}
