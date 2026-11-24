package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// Security-relevant branches the flow tests do not reach on their own.

// TestMatchingKeysFilters: only public signature keys whose kid and alg fit
// the token header may verify an ID token. An encryption key, a key pinned
// to another algorithm and a private or symmetric key are never candidates.
func TestMatchingKeysFilters(t *testing.T) {
	t.Parallel()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &ec.PublicKey
	keys := []jose.JSONWebKey{
		{Key: pub, KeyID: "enc", Use: "enc"},
		{Key: pub, KeyID: "rs", Algorithm: "RS256"},
		{Key: ec, KeyID: "private"},
		{Key: []byte("shared-secret-shared-secret-1234"), KeyID: "oct"},
		{Key: pub, KeyID: "good", Algorithm: "ES256", Use: "sig"},
		{Key: pub, KeyID: "no-alg"},
	}
	ids := func(ks []jose.JSONWebKey) string {
		var out []string
		for _, k := range ks {
			out = append(out, k.KeyID)
		}
		return strings.Join(out, ",")
	}
	for _, kid := range []string{"enc", "rs", "private", "oct"} {
		if got := matchingKeys(keys, kid, "ES256"); len(got) != 0 {
			t.Errorf("kid %s: unusable key offered: %s", kid, ids(got))
		}
	}
	if got := ids(matchingKeys(keys, "good", "ES256")); got != "good" {
		t.Errorf("kid good: got %q", got)
	}
	// Without a kid every usable key is tried, and only those.
	if got := ids(matchingKeys(keys, "", "ES256")); got != "good,no-alg" {
		t.Errorf("no kid: got %q, want good,no-alg", got)
	}
}

func TestVerifyIDTokenTimeAndKeyEdgeCases(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	now := env.clock.Now()
	claims := as.validClaims(now)
	claims["nbf"] = now.Add(time.Hour).Unix()
	if _, err := env.client.VerifyIDToken(context.Background(), as.idToken(claims), ""); !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("an ID token not valid for another hour: err = %v", err)
	}

	noJWKS := newFakeAS(t)
	noJWKS.setMetadata("jwks_uri", "")
	env2 := newTestEnv(t, noJWKS)
	_, err := env2.client.VerifyIDToken(context.Background(), noJWKS.idToken(noJWKS.validClaims(env2.clock.Now())), "")
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("no jwks_uri: err = %v, want ErrInvalidIDToken rather than an unverified token", err)
	}
}

func TestEntraTidCannotRewriteIssuerPath(t *testing.T) {
	t.Parallel()
	md := &Metadata{Issuer: "https://login.microsoftonline.com/{tenantid}/v2.0"}
	c := &Client{cfg: config{tenantIssuer: true}}
	for _, tid := range []string{"abc/evil", "abc?x", "abc#x"} {
		iss := strings.ReplaceAll(md.Issuer, "{tenantid}", tid)
		if c.idTokenIssuerOK(md, &rawClaims{Iss: iss, Tid: tid}) {
			t.Errorf("tid %q accepted", tid)
		}
	}
}

// TestCallbackHandlerRejects: the loopback listener answers only a GET on
// the redirect path with the right state, and only once.
func TestCallbackHandlerRejects(t *testing.T) {
	t.Parallel()
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	const state = "the-state"
	md := &Metadata{Issuer: "https://as.example"}
	results := make(chan callbackResult, 2)
	h := c.callbackHandler(md, state, results)
	serve := func(method, target string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, http.NoBody))
		return rec.Code
	}

	if code := serve(http.MethodGet, "/other?code=x&state="+state); code != http.StatusNotFound {
		t.Errorf("another path: status %d, want 404", code)
	}
	if code := serve(http.MethodPost, "/callback?code=x&state="+state); code != http.StatusNotFound {
		t.Errorf("POST: status %d, want 404", code)
	}
	if code := serve(http.MethodGet, "/callback?code=x&state=wrong"); code != http.StatusBadRequest {
		t.Errorf("wrong state: status %d, want 400", code)
	}
	if len(results) != 0 {
		t.Fatal("a rejected request produced a result")
	}
	if code := serve(http.MethodGet, "/callback?code=first&state="+state); code != http.StatusOK {
		t.Fatalf("valid redirect: status %d", code)
	}
	if code := serve(http.MethodGet, "/callback?code=second&state="+state); code != http.StatusBadRequest {
		t.Errorf("second redirect: status %d, want 400", code)
	}
	if len(results) != 1 {
		t.Fatalf("%d results, want exactly the first redirect", len(results))
	}
	if res := <-results; res.err != nil || res.code != "first" {
		t.Fatalf("result %+v, want the first code", res)
	}
}

// TestTransportAuthorizesEdgeCases: the access token never goes to a
// non-web scheme, nor in clear text to a remote host, also not when a
// redirect leads there.
func TestTransportAuthorizesEdgeCases(t *testing.T) {
	t.Parallel()
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.Transport(nil, WithAllowedOrigins("https://api.example", "http://api.example")).(*transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	req := func(raw string, redirect bool) *http.Request {
		r := httptest.NewRequest(http.MethodGet, raw, http.NoBody)
		if redirect {
			r.Response = &http.Response{StatusCode: http.StatusFound}
		}
		return r
	}
	if _, err := tr.authorizes(req("ftp://api.example/x", false)); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("ftp: err = %v, want ErrOriginNotAllowed", err)
	}
	// Plain http to a remote host is refused even for an allowed origin.
	if _, err := tr.authorizes(req("http://api.example/x", false)); !errors.Is(err, ErrInsecureEndpoint) {
		t.Errorf("http: err = %v, want ErrInsecureEndpoint", err)
	}
	if ok, err := tr.authorizes(req("http://api.example/x", true)); ok || err != nil {
		t.Errorf("redirect to http: authorized=%v err=%v, want followed without the token", ok, err)
	}
	if ok, err := tr.authorizes(req("https://cdn.example/x", true)); ok || err != nil {
		t.Errorf("redirect to another origin: authorized=%v err=%v", ok, err)
	}
	if ok, err := tr.authorizes(req("https://API.example:443/x", true)); !ok || err != nil {
		t.Errorf("redirect within the allowed origin: authorized=%v err=%v", ok, err)
	}
}

// TestTransportDoesNotReplayUnrewindableBody: a 401 invalid_token for a
// request whose body cannot be sent again is returned as it is, without a
// refresh and without a second request carrying an empty body.
func TestTransportDoesNotReplayUnrewindableBody(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(rs.Close)
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	ctx := context.Background()
	if err := env.client.save(ctx, &storage.Token{
		AccessToken: "at-1", TokenType: TokenTypeBearer, RefreshToken: "rt-1", Expiry: env.clock.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: env.client.Transport(nil)}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, rs.URL, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || calls.Load() != 1 {
		t.Fatalf("status %d after %d calls, want the 401 from a single call", resp.StatusCode, calls.Load())
	}
	if n := len(as.requestsTo("/token")); n != 0 {
		t.Fatalf("%d refreshes for a request that cannot be replayed", n)
	}
}

// failingSet is a store whose writes can be switched off.
type failingSet struct {
	storage.Provider
	fail atomic.Bool
}

func (f *failingSet) Set(ctx context.Context, key storage.Key, tok *storage.Token) error {
	if f.fail.Load() {
		return errors.New("disk full")
	}
	return f.Provider.Set(ctx, key, tok)
}

// TestRefreshThatCannotBeStoredFails: with rotation the old refresh token
// is spent once the server answered, so a renewed token set that cannot be
// stored must surface as an error, never be used as if all went well.
func TestRefreshThatCannotBeStoredFails(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2",
		})
	})
	store := &failingSet{Provider: storage.NewMemory()}
	env := newTestEnv(t, as, WithStorage(store))
	ctx := context.Background()
	if err := env.client.save(ctx, &storage.Token{
		AccessToken: "at-1", TokenType: TokenTypeBearer, RefreshToken: "rt-1", Expiry: env.clock.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	store.fail.Store(true)
	tok, err := env.client.Token(ctx)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("Token = %v, %v; want the storage error", tok, err)
	}
	if n := len(as.requestsTo("/token")); n != 1 {
		t.Fatalf("%d token requests, want one refresh", n)
	}
}

// TestPushAuthorizationRequestRefusesBadRequestURI: the request_uri goes
// into the URL the browser opens, so a missing, oversized or
// whitespace-carrying one is refused.
func TestPushAuthorizationRequestRefusesBadRequestURI(t *testing.T) {
	t.Parallel()
	for name, resp := range map[string]map[string]any{
		"missing":    {"expires_in": 60},
		"whitespace": {"request_uri": "urn:x a\r\nb", "expires_in": 60},
		"too long":   {"request_uri": "urn:" + strings.Repeat("a", maxURILen), "expires_in": 60},
		"not string": {"request_uri": 42, "expires_in": 60},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			as := newFakeAS(t)
			as.handle("/par", func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(w, http.StatusCreated, resp)
			})
			env := newTestEnv(t, as)
			md := &Metadata{Issuer: as.URL, PushedAuthorizationRequestEndpoint: as.URL + "/par"}
			_, err := env.client.pushAuthorizationRequest(context.Background(), md, url.Values{"state": {"s"}})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

// TestParseDPoPKeyRefuses: a stored DPoP key must be a private signing key
// for an algorithm the client supports.
func TestParseDPoPKeyRefuses(t *testing.T) {
	t.Parallel()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(k jose.JSONWebKey) string {
		b, err := k.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for name, enc := range map[string]string{
		"public only":    encode(jose.JSONWebKey{Key: &ec.PublicKey, Algorithm: "ES256"}),
		"HMAC algorithm": encode(jose.JSONWebKey{Key: ec, Algorithm: "HS256"}),
		"no algorithm":   encode(jose.JSONWebKey{Key: ec}),
		"symmetric":      encode(jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), Algorithm: "HS256"}),
		"garbage":        "{",
	} {
		if _, err := parseDPoPKey(enc); err == nil {
			t.Errorf("%s: stored key accepted", name)
		}
	}
	if _, err := parseDPoPKey(encode(jose.JSONWebKey{Key: ec, Algorithm: "ES256"})); err != nil {
		t.Fatalf("a valid key refused: %v", err)
	}
}

// TestTLSErrorIsSanitized: a network attacker without a valid certificate
// chooses the DNS names in the one it presents, and Go's verifier quotes
// them in its error (x509.HostnameError). That error reaches the terminal
// through the commands, so it must not carry escape sequences.
func TestTLSErrorIsSanitized(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const evil = "evil\x1b]0;PWNED\a\x1b[31mRED"
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attacker"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{evil}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// Trusting the certificate makes the hostname check, which quotes the
	// SANs, the one that fails.
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	// A host name, not the IP, so the check compares DNS names and quotes
	// the certificate's.
	issuer := "https://localhost:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	c, err := NewClient(WithDiscoveryURL(issuer+"/.well-known/openid-configuration"), WithClientID("c"),
		WithStorage(storage.NewMemory()), WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Metadata(context.Background())
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("err = %v, want an x509.HostnameError underneath", err)
	}
	assertPrintable(t, "TLS error", err.Error())
	if !strings.Contains(err.Error(), "PWNED") {
		t.Fatalf("the error lost its content: %q", err.Error())
	}
}
