package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

func TestStorageIssuer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts []Option
		want string
	}{
		{"issuer", []Option{WithIssuer("https://as.example/t")}, "https://as.example/t"},
		{"OIDC discovery URL", []Option{WithDiscoveryURL("https://as.example/t/.well-known/openid-configuration")}, "https://as.example/t"},
		{"RFC 8414 discovery URL", []Option{WithDiscoveryURL("https://as.example/.well-known/oauth-authorization-server/t")}, "https://as.example/t"},
		{"odd discovery URL", []Option{WithDiscoveryURL("https://as.example/meta")}, "https://as.example/meta"},
		{"token endpoint only", []Option{WithTokenEndpoint("https://as.example/token")}, "https://as.example/token"},
		{"preset fallback only", []Option{func(c *config) { c.fallbacks.Token = "https://gh.example/token" }}, "https://gh.example/token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewClient(append([]Option{WithClientID("c"), WithStorage(storage.NewMemory())}, tc.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.StorageKey().Issuer; got != tc.want {
				t.Fatalf("storage issuer = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStorageAudienceSortsResources(t *testing.T) {
	t.Parallel()
	a, _ := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithAudience("aud"),
		WithResource("https://b.example", "https://a.example", "https://a.example"), WithStorage(storage.NewMemory()))
	b, _ := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithAudience("aud"),
		WithResource("https://a.example", "https://b.example"), WithStorage(storage.NewMemory()))
	if a.StorageKey() != b.StorageKey() || a.StorageKey().Audience != "aud https://a.example https://b.example" {
		t.Fatalf("keys differ: %+v %+v", a.StorageKey(), b.StorageKey())
	}
}

func TestHeadless(t *testing.T) {
	// Not parallel: it changes the environment.
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "DISPLAY", "WAYLAND_DISPLAY"} {
		t.Setenv(v, "")
	}
	t.Setenv("SSH_TTY", "/dev/pts/1")
	if !headless() {
		t.Fatal("an SSH session must count as headless")
	}
	t.Setenv("SSH_TTY", "")
	t.Setenv("DISPLAY", ":0")
	if headless() {
		t.Fatal("a session with a display is not headless")
	}
	c := &Client{cfg: defaultConfig()}
	if c.browserUsable() != !headless() {
		t.Fatal("the default browser mode follows headless()")
	}
}

func TestTryOpenBrowser(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()), WithBrowser(true),
		WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		WithBrowserOpener(func(context.Context, string) error { return errors.New("no opener") }))
	if err != nil {
		t.Fatal(err)
	}
	if c.tryOpenBrowser(t.Context(), "https://as.example/x") {
		t.Fatal("a failing opener reported success")
	}
	if !strings.Contains(logs.String(), "could not open browser") {
		t.Fatalf("the failure was not logged: %s", logs.String())
	}
}

func TestSafeBrowserURL(t *testing.T) {
	t.Parallel()
	c := &Client{cfg: defaultConfig()}
	for raw, ok := range map[string]bool{
		"https://as.example/device":   true,
		"http://127.0.0.1:8080/x":     true,
		"http://dev.localhost:8080/x": true, // browsers resolve *.localhost themselves
		"http://as.example/device":    false,
		"https://u:p@as.example/":     false,
		"javascript:alert(1)":         false,
		"file:///etc/passwd":          false,
		"ms-settings:display":         false,
		"https:///nohost":             false,
		"\\\\attacker\\share":         false,
		"https://as.example/%zz":      false,
		"custom-app://callback?x=1":   false,
		"https://xn--80ak6aa92e.com/": true,
		// The query is printed as it came: C1 controls and bidi
		// overrides there are refused; elsewhere they are escaped.
		"https://as.example/d?user_code=ABCD&x=%E2%80%AE": true,
		"https://as.example/d?a=\u009b31m":                false,
		"https://as.example/d?a=\u202egnp.exe":            false,
		"https://as.example/\u202e?a=1":                   true,
	} {
		_, err := c.safeBrowserURL(raw)
		if (err == nil) != ok {
			t.Errorf("safeBrowserURL(%q) err = %v, want ok=%v", raw, err, ok)
		}
	}
	c.cfg.insecureHTTP = true
	if _, err := c.safeBrowserURL("http://as.example/device"); err != nil {
		t.Fatalf("WithInsecureHTTP must allow plain http: %v", err)
	}
}

func TestSameOriginRedirects(t *testing.T) {
	t.Parallel()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{"issuer": "x"})
	}))
	t.Cleanup(other.Close)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/doc", http.StatusFound)
		case "/away":
			http.Redirect(w, r, other.URL+"/doc", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			writeJSONResponse(w, http.StatusOK, map[string]any{"issuer": srv.URL})
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(WithIssuer(srv.URL), WithClientID("c"), WithStorage(storage.NewMemory()), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _, err := c.getJSON(t.Context(), "discovery", srv.URL+"/moved"); err != nil || status != http.StatusOK {
		t.Fatalf("same-origin redirect: %d %v", status, err)
	}
	for _, p := range []string{"/away", "/loop"} {
		if _, _, _, err := c.getJSON(t.Context(), "discovery", srv.URL+p); err == nil {
			t.Fatalf("%s: redirect followed", p)
		}
	}
}

func TestRedactURLError(t *testing.T) {
	t.Parallel()
	err := redactURLError(&url.Error{Op: "Post", URL: "https://u:p@as.example/token?code=secret", Err: io.EOF})
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "u:p") || !errors.Is(err, io.EOF) {
		t.Fatalf("redactURLError: %v", err)
	}
	if plain := errors.New("x"); !errors.Is(redactURLError(plain), plain) || redactURLError(plain).Error() != "x" {
		t.Fatal("a non-URL error must pass through")
	}
}

func TestClientDescriptions(t *testing.T) {
	t.Parallel()
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithClientSecret("s3cret"), WithStorage(storage.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "client", c)
	if strings.Contains(b.String()+c.String(), "s3cret") || !strings.Contains(b.String(), `"confidential":true`) {
		t.Fatalf("descriptions: %s %s", b.String(), c.String())
	}
	// %#v would print the unexported fields, secret and keys included,
	// without GoString.
	for _, format := range []string{"%v", "%+v", "%s", "%#v"} {
		if out := fmt.Sprintf(format, c); strings.Contains(out, "s3cret") {
			t.Fatalf("%s prints the secret: %s", format, out)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithPrivateKeyJWT(key, "k1"), WithStorage(storage.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	if out := fmt.Sprintf("%#v", signed); strings.Contains(out, "PrivateKey") || strings.Contains(out, "assertionKey") {
		t.Fatalf("%%#v prints the signing key: %s", out)
	}
	public, _ := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if !strings.Contains(public.String(), `secret=""`) {
		t.Fatalf("public client: %s", public)
	}
	if GrantDeviceCode.String() != string(GrantDeviceCode) {
		t.Fatal("GrantType.String")
	}
	if (&builtinAuth{method: ClientAuthSecretPost}).Method() != ClientAuthSecretPost ||
		(&jwtAuth{method: ClientAuthPrivateKeyJWT}).Method() != ClientAuthPrivateKeyJWT {
		t.Fatal("Method")
	}
	select {
	case <-systemClock{}.After(time.Nanosecond):
	case <-time.After(5 * time.Second):
		t.Fatal("systemClock.After did not fire")
	}
}

func TestAssertionAlgKeyTypes(t *testing.T) {
	t.Parallel()
	gen := func(c elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		key  any
		want string
	}{
		"P-256":   {gen(elliptic.P256()), "ES256"},
		"P-384":   {gen(elliptic.P384()), "ES384"},
		"P-521":   {gen(elliptic.P521()), "ES512"},
		"P-224":   {gen(elliptic.P224()), ""},
		"Ed25519": {edKey, "EdDSA"},
	} {
		alg, err := assertionAlg(tc.key.(crypto.Signer), nil)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if err != nil || string(alg) != tc.want {
			t.Errorf("%s: %s %v, want %s", name, alg, err, tc.want)
		}
	}
	if _, err := assertionAlg(nil, nil); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestCommandContextDefaults(t *testing.T) {
	t.Parallel()
	if commandContext(&cobra.Command{}) == nil {
		t.Fatal("commandContext without a context must fall back to Background")
	}
	if identity(&Status{Name: "n", Subject: "s"}) != "n" || identity(&Status{Subject: "s"}) != "s" {
		t.Fatal("identity fallbacks")
	}
}

func TestTransportClosesBodyOnTokenError(t *testing.T) {
	t.Parallel()
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	body := &trackingBody{Reader: strings.NewReader("payload")}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.example/x", body)
	if _, err := c.Transport(nil).RoundTrip(req); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("RoundTrip: %v", err)
	}
	if !body.closed {
		t.Fatal("RoundTrip must close the request body when it fails before sending")
	}
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

func TestUnixField(t *testing.T) {
	t.Parallel()
	var fields map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"small":1700000000,"big":99999999999,"neg":-1,"str":"1700000000","bad":"x"}`))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		t.Fatal(err)
	}
	if unixField(fields, "small").Unix() != 1700000000 || unixField(fields, "big").Unix() != 99999999999 ||
		!unixField(fields, "neg").IsZero() || unixField(fields, "str").Unix() != 1700000000 ||
		!unixField(fields, "bad").IsZero() || !unixField(fields, "missing").IsZero() {
		t.Fatalf("unixField: %v", fields)
	}
}

func TestUnverifiedClaims(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "a.b", "a.!!!.c", "a." + "bm90IGpzb24" + ".c"} {
		if _, err := unverifiedClaims(raw); !errors.Is(err, ErrInvalidIDToken) {
			t.Errorf("unverifiedClaims(%q) = %v", raw, err)
		}
	}
	// email_verified as a string, as some providers send it.
	payload := `{"sub":"s","aud":["c"],"email_verified":"true","exp":1}`
	tok := "e30." + b64(payload) + ".sig"
	claims, err := unverifiedClaims(tok)
	if err != nil || !claims.EmailVerified || claims.Subject != "s" {
		t.Fatalf("claims: %+v %v", claims, err)
	}
	if _, err := unverifiedClaims("e30." + b64(`{"aud":5}`) + ".sig"); err == nil {
		t.Fatal("aud of the wrong type accepted")
	}
	if _, err := unverifiedClaims("e30." + b64(`{"exp":"soon"}`) + ".sig"); err == nil {
		t.Fatal("exp of the wrong type accepted")
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
