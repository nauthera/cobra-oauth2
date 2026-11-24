package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

const parRequestURI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"

// parOpener plays the browser for a pushed authorization request: the
// authorization URL may carry only client_id and request_uri, and the
// pushed parameters stand in for the query.
func parOpener(t *testing.T, b *browserAS, pushed func() url.Values) BrowserOpener {
	return func(_ context.Context, raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		if len(q) != 2 || q.Get("client_id") != testClientID || q.Get("request_uri") != parRequestURI {
			t.Errorf("authorization URL with PAR carries more than client_id and request_uri: %s", raw)
		}
		p := pushed()
		full := *u
		full.RawQuery = p.Encode()
		b.mu.Lock()
		b.authURL, b.challenge = &full, p.Get("code_challenge")
		b.mu.Unlock()
		go func() {
			resp, err := http.Get(p.Get("redirect_uri") + "?" + okRedirect(b.URL)(p).Encode())
			if err != nil {
				t.Errorf("redirect: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
}

func TestBrowserLoginWithPAR(t *testing.T) {
	t.Parallel()
	b := newBrowserAS(t)
	b.setMetadata("pushed_authorization_request_endpoint", b.URL+"/par")
	b.setMetadata("require_pushed_authorization_requests", true)
	b.setMetadata("dpop_signing_alg_values_supported", []string{"ES256"})
	var (
		mu     sync.Mutex
		pushed url.Values
		header http.Header
	)
	b.handle("/par", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pushed, header = r.PostForm, r.Header.Clone()
		mu.Unlock()
		writeJSONResponse(w, http.StatusCreated, map[string]any{"request_uri": parRequestURI, "expires_in": 60})
	})
	getPushed := func() url.Values {
		mu.Lock()
		defer mu.Unlock()
		return pushed
	}
	env := newTestEnv(t, b.fakeAS, WithBrowser(true), WithBrowserOpener(parOpener(t, b, getPushed)),
		WithClientSecret("s3cret"), WithResource("https://api.example/", "https://other.example/"),
		WithDPoPAuto(), WithAuthParam("request_uri", "must-not-be-pushed"))
	env.clock.now = time.Now()

	tok, err := env.client.BrowserLogin(context.Background())
	if err != nil {
		t.Fatalf("BrowserLogin with PAR: %v", err)
	}
	p := getPushed()
	switch {
	case p.Get("response_type") != "code" || p.Get("code_challenge_method") != "S256" || p.Get("state") == "":
		t.Fatalf("pushed parameters: %v", p)
	case p.Get("client_id") != testClientID:
		t.Fatal("client_id missing from a pushed request with Basic authentication")
	case !strings.HasPrefix(header.Get("Authorization"), "Basic "):
		t.Fatal("the pushed request is not client-authenticated")
	case !slices.Equal(p["resource"], []string{"https://api.example/", "https://other.example/"}):
		t.Fatalf("resource indicators: %v", p["resource"])
	case p.Has("request_uri"):
		t.Fatal("request_uri was pushed")
	}
	key, err := parseDPoPKey(tok.DPoPKey)
	if err != nil {
		t.Fatalf("DPoP key: %v", err)
	}
	if p.Get("dpop_jkt") != key.jkt {
		t.Fatal("dpop_jkt in the pushed request does not name the client's key")
	}
	tokReq := b.requestsTo("/token")[0]
	if _, jkt, err := verifyProof(tokReq.Header.Get("DPoP")); err != nil || jkt != key.jkt {
		t.Fatalf("the code was redeemed without a proof made with the bound key: %v", err)
	}
	if !slices.Equal(tokReq.Form["resource"], p["resource"]) {
		t.Fatal("resource indicators missing from the code redemption")
	}
}

func TestUsePAR(t *testing.T) {
	t.Parallel()
	withEP := &Metadata{PushedAuthorizationRequestEndpoint: "https://as.example/par"}
	none := &Metadata{}
	cases := []struct {
		mode    PARMode
		md      *Metadata
		want    bool
		wantErr bool
	}{
		{PARIfRequired, withEP, false, false},
		{PARIfRequired, &Metadata{PushedAuthorizationRequestEndpoint: "x", RequirePushedAuthorizationRequests: true}, true, false},
		{PARIfAvailable, withEP, true, false},
		{PARIfAvailable, none, false, false},
		{PARAlways, withEP, true, false},
		{PARAlways, none, false, true},
	}
	for _, tc := range cases {
		c := &Client{cfg: config{par: tc.mode}}
		got, err := c.usePAR(tc.md)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("mode %q: got %v, %v", tc.mode, got, err)
		}
	}
}

// assertionServer verifies client assertions at its token endpoint.
func assertionServer(t *testing.T, pub any, alg jose.SignatureAlgorithm, wantAud func(as *fakeAS) string) (*fakeAS, func() []map[string]any) {
	t.Helper()
	as := newFakeAS(t)
	var (
		mu     sync.Mutex
		claims []map[string]any
	)
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		f := r.PostForm
		if f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			f.Has("client_secret") || r.Header.Get("Authorization") != "" {
			oauthError(w, http.StatusBadRequest, "invalid_client")
			return
		}
		jws, err := jose.ParseSignedCompact(f.Get("client_assertion"), []jose.SignatureAlgorithm{alg})
		if err != nil {
			t.Errorf("assertion: %v", err)
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		payload, err := jws.Verify(pub)
		if err != nil {
			t.Errorf("assertion signature: %v", err)
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		var cl map[string]any
		_ = json.Unmarshal(payload, &cl)
		cl["kid"] = jws.Signatures[0].Header.KeyID
		mu.Lock()
		claims = append(claims, cl)
		mu.Unlock()
		if cl["iss"] != testClientID || cl["sub"] != testClientID || cl["aud"] != wantAud(as) {
			t.Errorf("assertion claims: %v", cl)
		}
		if exp, iat := cl["exp"].(float64), cl["iat"].(float64); exp-iat <= 0 || exp-iat > 300 {
			t.Errorf("assertion lifetime %v s", exp-iat)
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "cc", "token_type": "Bearer", "expires_in": 60})
	})
	return as, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return claims
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerAud := func(as *fakeAS) string { return as.URL }
	as, claims := assertionServer(t, &key.PublicKey, jose.ES256, issuerAud)
	env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithPrivateKeyJWT(key, "key-1"))
	for i := 0; i < 2; i++ {
		if _, err := env.client.ClientCredentials(context.Background()); err != nil {
			t.Fatalf("client credentials with private_key_jwt: %v", err)
		}
	}
	got := claims()
	if len(got) != 2 || got[0]["jti"] == got[1]["jti"] || got[0]["kid"] != "key-1" {
		t.Fatalf("assertions must carry the kid and a unique jti: %v", got)
	}

	t.Run("token endpoint audience", func(t *testing.T) {
		t.Parallel()
		as, _ := assertionServer(t, &key.PublicKey, jose.ES256, func(as *fakeAS) string { return as.URL + "/token" })
		env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithPrivateKeyJWT(key, ""),
			WithAssertionAudience(AssertionAudienceTokenEndpoint))
		if _, err := env.client.ClientCredentials(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("algorithm not accepted by the server", func(t *testing.T) {
		t.Parallel()
		as, _ := assertionServer(t, &key.PublicKey, jose.ES256, issuerAud)
		as.setMetadata("token_endpoint_auth_signing_alg_values_supported", []string{"RS256"})
		env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithPrivateKeyJWT(key, ""))
		if _, err := env.client.ClientCredentials(context.Background()); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("client_secret_jwt", func(t *testing.T) {
		t.Parallel()
		secret := strings.Repeat("k", 32)
		as, _ := assertionServer(t, []byte(secret), jose.HS256, issuerAud)
		env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithClientSecret(secret), WithAuthMethod(ClientAuthSecretJWT))
		if _, err := env.client.ClientCredentials(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAssertionAlg(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if alg, _ := assertionAlg(rsaKey, nil); alg != jose.RS256 {
		t.Fatalf("RSA default %s", alg)
	}
	if alg, _ := assertionAlg(rsaKey, []string{"PS256", "ES256"}); alg != jose.PS256 {
		t.Fatalf("RSA with PS256 only: %s", alg)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if alg, _ := assertionAlg(p384, nil); alg != jose.ES384 {
		t.Fatalf("P-384: %s", alg)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := assertionAlg(small, nil); err == nil {
		t.Fatal("a 1024-bit RSA key was accepted")
	}
	if _, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithAuthMethod(ClientAuthPrivateKeyJWT)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("private_key_jwt without a key: %v", err)
	}
}

func TestResourceIndicators(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, standardDA(as.URL))
	})
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm.Get("grant_type") == "refresh_token" {
			writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "at-2", "expires_in": 60})
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "at-1", "expires_in": 60, "refresh_token": "rt"})
	})
	resources := []string{"https://b.example/api", "https://a.example/api"}
	env := newTestEnv(t, as, WithFlow(FlowDevice), WithResource(resources...))
	if _, err := env.client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(time.Hour)
	if _, err := env.client.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range append(as.requestsTo("/device_authorization"), as.requestsTo("/token")...) {
		if !slices.Equal(r.Form["resource"], resources) {
			t.Fatalf("%s %s: resource = %v", r.Path, r.Form.Get("grant_type"), r.Form["resource"])
		}
	}
	// The storage key depends on the resource set, not its order.
	other := newTestEnv(t, as, WithResource(resources[1], resources[0]))
	plain := newTestEnv(t, as)
	if other.client.StorageKey() != env.client.StorageKey() || plain.client.StorageKey() == env.client.StorageKey() {
		t.Fatalf("storage keys: %+v %+v %+v", env.client.StorageKey(), other.client.StorageKey(), plain.client.StorageKey())
	}
	for _, bad := range []string{"relative/path", "https://api.example/#frag"} {
		if _, err := NewClient(WithIssuer(as.URL), WithClientID("c"), WithResource(bad)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("resource %q accepted: %v", bad, err)
		}
	}
}

func TestExchangeToken(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("grant_types_supported", []string{"urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"})
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		f := r.PostForm
		if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || f.Get("subject_token") != "stored-at" ||
			f.Get("subject_token_type") != string(AccessTokenType) {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if f.Get("requested_token_type") == string(IDTokenType) {
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"access_token": "an-id-token", "token_type": "N_A",
				"issued_token_type": IDTokenType,
			})
			return
		}
		if !slices.Equal(f["audience"], []string{"svc-a", "svc-b"}) || f.Get("resource") != "https://api.example/" || f.Get("scope") != "read write" {
			oauthError(w, http.StatusBadRequest, "invalid_target")
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"access_token": "exchanged", "token_type": "Bearer",
			"issued_token_type": AccessTokenType, "expires_in": 300,
		})
	})
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "stored-at", Expiry: env.clock.Now().Add(time.Hour)})

	res, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{
		Audience: []string{"svc-a", "svc-b"}, Resource: []string{"https://api.example/"}, Scope: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if res.Token.AccessToken != "exchanged" || res.IssuedTokenType != AccessTokenType || res.Token.Expiry.IsZero() {
		t.Fatalf("result: %+v %v", res, res.Token)
	}
	res, err = env.client.ExchangeToken(context.Background(), ExchangeRequest{
		SubjectToken: "stored-at", SubjectTokenType: AccessTokenType, RequestedTokenType: IDTokenType,
	})
	if err != nil || res.Token.TokenType != TokenTypeNA || res.IssuedTokenType != IDTokenType {
		t.Fatalf("N_A exchange: %+v, %v", res, err)
	}
	if _, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{SubjectToken: "x"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing subject token type: %v", err)
	}
	if _, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{
		SubjectToken: "x", SubjectTokenType: AccessTokenType, ActorToken: "y",
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("actor token without type: %v", err)
	}
}

func TestExchangeTokenUnsupported(t *testing.T) {
	t.Parallel()
	t.Run("not advertised", func(t *testing.T) {
		t.Parallel()
		as := newFakeAS(t)
		as.setMetadata("grant_types_supported", []string{"authorization_code"})
		env := newTestEnv(t, as)
		_, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{SubjectToken: "x", SubjectTokenType: JWTTokenType})
		if !errors.Is(err, ErrUnsupportedFlow) || len(as.requestsTo("/token")) != 0 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("503 like nauthera", func(t *testing.T) {
		t.Parallel()
		as := newFakeAS(t)
		as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		})
		env := newTestEnv(t, as)
		_, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{SubjectToken: "x", SubjectTokenType: JWTTokenType})
		if !errors.Is(err, ErrUnsupportedFlow) || !errors.Is(err, ErrTemporarilyUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no issued_token_type", func(t *testing.T) {
		t.Parallel()
		as := newFakeAS(t)
		as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "a", "token_type": "Bearer"})
		})
		env := newTestEnv(t, as)
		_, err := env.client.ExchangeToken(context.Background(), ExchangeRequest{SubjectToken: "x", SubjectTokenType: JWTTokenType})
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestIntrospect(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("introspection_endpoint", as.URL+"/introspect")
	as.handle("/introspect", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != testClientID || pass != "s3cret" {
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		if r.PostForm.Get("token") != "live" {
			writeJSONResponse(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"active": true, "scope": "read write", "client_id": "svc", "sub": "user-1", "aud": []string{"a", "b"},
			"exp": "1900000000", "iat": 1800000000, "iss": as.URL, "token_type": "Bearer",
		})
	})
	env := newTestEnv(t, as, WithClientSecret("s3cret"))
	in, err := env.client.Introspect(context.Background(), "live")
	if err != nil {
		t.Fatal(err)
	}
	if !in.Active || in.Subject != "user-1" || in.Scope != "read write" || !slices.Equal(in.Audience, []string{"a", "b"}) ||
		in.Expiry.Unix() != 1900000000 || in.IssuedAt.Unix() != 1800000000 || in.Raw["client_id"] != "svc" {
		t.Fatalf("introspection: %+v", in)
	}
	if in, err := env.client.Introspect(context.Background(), "dead"); err != nil || in.Active {
		t.Fatalf("inactive token: %+v, %v", in, err)
	}

	public := newTestEnv(t, as)
	if _, err := public.client.Introspect(context.Background(), "live"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("public client: %v", err)
	}
	bare := newFakeAS(t)
	noEP := newTestEnv(t, bare, WithClientSecret("s3cret"))
	if _, err := noEP.client.Introspect(context.Background(), "live"); !errors.Is(err, ErrIntrospectionUnsupported) {
		t.Fatalf("no endpoint: %v", err)
	}
	if _, err := parseIntrospection(map[string]any{}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("missing active: %v", err)
	}
}

func TestLogoutEndSession(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		opts     EndSessionOptions
		wantHint bool
	}{
		{"defaults", EndSessionOptions{}, false},
		{"hint and redirect", EndSessionOptions{IDTokenHint: true, PostLogoutRedirectURI: "https://app.example/bye"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			as := newFakeAS(t)
			as.setMetadata("revocation_endpoint", nil)
			as.setMetadata("end_session_endpoint", as.URL+"/logout?ui=1")
			var opened string
			env := newTestEnv(t, as, WithEndSession(tc.opts), WithBrowser(true),
				WithBrowserOpener(func(_ context.Context, u string) error { opened = u; return nil }))
			storeToken(t, env, &storage.Token{AccessToken: "at", IDToken: "the-id-token"})
			if err := env.client.Logout(context.Background()); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(opened)
			if err != nil || u.Path != "/logout" {
				t.Fatalf("opened %q", opened)
			}
			q := u.Query()
			if q.Get("ui") != "1" || q.Get("client_id") != testClientID {
				t.Fatalf("logout URL %s", opened)
			}
			if q.Has("id_token_hint") != tc.wantHint || q.Get("post_logout_redirect_uri") != tc.opts.PostLogoutRedirectURI {
				t.Fatalf("logout URL %s", opened)
			}
			if !strings.Contains(env.errOut.String(), "/logout?") {
				t.Fatalf("logout URL not printed:\n%s", env.errOut.String())
			}
			if _, err := env.client.StoredToken(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
				t.Fatal("tokens not deleted")
			}
		})
	}
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	if _, err := env.client.EndSessionURL(context.Background(), ""); !errors.Is(err, ErrEndSessionUnsupported) {
		t.Fatalf("no end_session_endpoint: %v", err)
	}
	if _, err := NewClient(WithIssuer(as.URL), WithClientID("c"),
		WithEndSession(EndSessionOptions{PostLogoutRedirectURI: "http://evil.example/"})); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plain-http post_logout_redirect_uri accepted: %v", err)
	}
}
