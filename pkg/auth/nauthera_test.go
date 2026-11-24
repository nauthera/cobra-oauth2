package auth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
)

// This suite runs the library against a fake server configured to behave
// like nauthera-server (testdata/nauthera/README.md lists the sources):
// https only, exact issuer, S256 PKCE, RFC 9207 iss, refresh tokens only
// with offline_access, rotation with reuse detection, a DPoP nonce always
// required, interval enforcement in the device flow, confidential-only
// introspection and no token exchange.

const (
	nautheraCLI     = "nauthera-cli"
	nautheraService = "svc-reporting"
	// The secret has characters that RFC 6749 § 2.3.1's form-encoding of
	// Basic credentials must survive; nauthera form-decodes both parts.
	nautheraServiceSecret = "s3cr:et+/=&é %"

	grantDevice = "urn:ietf:params:oauth:grant-type:device_code"
)

func nautheraFixture(name string) string { return filepath.Join("testdata", "nauthera", name) }

func nautheraConfig(t *testing.T, discovery string) oauthtest.Config {
	t.Helper()
	return oauthtest.Config{
		TLS:      true,
		Metadata: oauthtest.LoadJSON(t, nautheraFixture(discovery)),
		Clients: []oauthtest.Client{
			{
				ID: nautheraCLI, RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
				Grants: []string{"authorization_code", "refresh_token", grantDevice},
			},
			{ID: nautheraService, Secret: nautheraServiceSecret, Grants: []string{"client_credentials"}},
		},
		RefreshPolicy:   oauthtest.RefreshRotate,
		RefreshScope:    "offline_access",
		DPoP:            oauthtest.DPoPPolicy{Enabled: true, RequireNonce: true},
		EnforceInterval: true,
		Quirks:          oauthtest.Quirks{ErrorURIBase: "https://nauthera.io/runbooks/oauth/"},
	}
}

// nautheraPreset is what an importer configures for a nauthera issuer; the
// env then points the issuer at the fake server.
func nautheraPreset() []auth.Option {
	return []auth.Option{auth.Nauthera("https://auth.example.com"), auth.WithClientID(nautheraCLI)}
}

func newNauthera(t *testing.T, mutate func(*oauthtest.Config), opts ...auth.Option) *env {
	t.Helper()
	cfg := nautheraConfig(t, "discovery.json")
	if mutate != nil {
		mutate(&cfg)
	}
	return newEnv(t, cfg, nautheraPreset(), opts...)
}

func TestNautheraDiscovery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		issuerPath string
		mode       oauthtest.DiscoveryMode
		wantFetch  int
	}{
		{"main organization", "", oauthtest.DiscoveryBoth, 1},
		{"tenant organization", "/orgs/acme", oauthtest.DiscoveryBoth, 1},
		// A deployment that only serves the RFC 8414 insert location: the
		// OIDC location 404s and the client moves on.
		{"tenant, RFC 8414 location only", "/orgs/acme", oauthtest.DiscoveryRFC8414, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newNauthera(t, func(c *oauthtest.Config) { c.IssuerPath, c.Discovery = tc.issuerPath, tc.mode })
			md, err := e.client.Metadata(t.Context())
			if err != nil {
				t.Fatalf("Metadata: %v", err)
			}
			if md.Issuer != e.as.Issuer() || md.TokenEndpoint != e.as.Issuer()+"/token" ||
				md.JWKSURI != e.as.Issuer()+"/.well-known/jwks.json" {
				t.Fatalf("metadata: %+v", md)
			}
			if !md.AuthorizationResponseIssParameterSupported || !slices.Equal(md.CodeChallengeMethodsSupported, []string{"S256"}) ||
				!slices.Contains(md.DPoPSigningAlgValuesSupported, "ES256") || md.RequirePushedAuthorizationRequests {
				t.Fatalf("capabilities: %+v", md)
			}
			if !md.SupportsGrant(auth.GrantDeviceCode) || md.SupportsGrant(auth.GrantTokenExchange) {
				t.Fatalf("grant_types_supported: %v", md.GrantTypesSupported)
			}
			if _, err := e.client.Metadata(t.Context()); err != nil {
				t.Fatal(err)
			}
			if n := len(e.as.Requests(oauthtest.EndpointDiscovery)); n != tc.wantFetch {
				t.Fatalf("%d discovery fetches, want %d (cached after the first success)", n, tc.wantFetch)
			}
		})
	}
}

func TestNautheraDiscoveryRefusesAnotherIssuer(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil)
	e.as.SetMetadata("issuer", "https://auth.attacker.example")
	_, err := e.client.Metadata(t.Context())
	wantErr(t, err, auth.ErrDiscovery, auth.ErrIssuerMismatch)
	if n := len(e.as.Requests(oauthtest.EndpointDiscovery)); n != 1 {
		t.Fatalf("a refused document must end the search, got %d fetches", n)
	}
}

func TestNautheraDeviceLogin(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, func(c *oauthtest.Config) {
		c.DeviceScript = []oauthtest.DeviceStep{
			oauthtest.DevicePending, oauthtest.DeviceSlowDown, oauthtest.DevicePending, oauthtest.DeviceApprove,
		}
	}, auth.WithFlow(auth.FlowDevice))

	tok := mustLogin(t, e.client)
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" || tok.TokenType != auth.TokenTypeBearer {
		t.Fatalf("token set: %v", tok)
	}
	if tok.Scope != "openid offline_access" {
		t.Fatalf("scope = %q", tok.Scope)
	}
	// RFC 8628 § 3.5: slow_down adds 5 s for good; the server, which
	// enforces the interval, would answer slow_down again otherwise.
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if got := e.clock.Waits(); !slices.Equal(got, want) {
		t.Fatalf("poll waits = %v, want %v", got, want)
	}
	if got := e.as.DeviceInterval(); got != 10 {
		t.Fatalf("server-side interval = %d s, want 10", got)
	}

	da := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0]
	if da.Form.Get("client_id") != nautheraCLI || da.Form.Get("scope") != "openid offline_access" ||
		da.Form.Has("client_secret") || da.Header.Get("Authorization") != "" || da.Form.Has("dpop_jkt") {
		t.Fatalf("device authorization request: %v %v", da.Form, da.Header)
	}
	prompt := e.errOut.String()
	if !strings.Contains(prompt, "WDJB-MJHT") || !strings.Contains(prompt, e.as.Issuer()+"/device") {
		t.Fatalf("prompt lacks the user code or verification URI:\n%s", prompt)
	}
	poll := e.as.Requests(oauthtest.EndpointToken)[0]
	assertNoSecret(t, "prompt", prompt, poll.Form.Get("device_code"))
	if e.out.String() != "" {
		t.Fatalf("the device flow wrote to stdout: %q", e.out.String())
	}

	stored, err := e.client.StoredToken(t.Context())
	if err != nil || stored.AccessToken != tok.AccessToken || stored.Issuer != e.as.Issuer() || stored.ClientID != nautheraCLI {
		t.Fatalf("stored token: %v %v", stored, err)
	}
	st, err := e.client.Status(t.Context())
	if err != nil || st.Subject != "user-1" || !st.HasRefreshToken {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestNautheraDeviceLoginOutcomes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*oauthtest.Config)
		want   error
	}{
		{"denied", func(c *oauthtest.Config) {
			c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DevicePending, oauthtest.DeviceDeny}
		}, auth.ErrAccessDenied},
		{"expired", func(c *oauthtest.Config) { c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DeviceExpire} }, auth.ErrExpiredToken},
		{"never approved", func(c *oauthtest.Config) {
			c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DevicePending}
			c.DeviceExpiresIn = 30
		}, auth.ErrExpiredToken},
		{"client lacks the device grant", func(c *oauthtest.Config) {
			c.Clients[0].Grants = []string{"authorization_code", "refresh_token"}
		}, auth.ErrUnauthorizedClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newNauthera(t, tc.mutate, auth.WithFlow(auth.FlowDevice))
			_, err := e.client.Login(t.Context())
			wantErr(t, err, tc.want)
			if _, err := e.client.StoredToken(t.Context()); !errors.Is(err, auth.ErrNotLoggedIn) {
				t.Fatalf("a failed login stored something: %v", err)
			}
		})
	}
}

func TestNautheraDeviceApprovalByUserCode(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, func(c *oauthtest.Config) { c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DevicePending} },
		auth.WithFlow(auth.FlowDevice))
	// The handler plays the user, who approves on another device. User
	// codes are compared without case and separators, as nauthera does.
	c := e.newClient(t, auth.WithFlow(auth.FlowDevice), auth.WithDeviceAuthorizationHandler(func(_ context.Context, da *auth.DeviceAuthorization) error {
		if !e.as.ApproveDevice(strings.ToLower(strings.ReplaceAll(da.UserCode, "-", ""))) {
			t.Error("no pending device session for the user code")
		}
		if strings.Contains(da.String(), "device-") {
			t.Errorf("DeviceAuthorization.String leaks the device code: %s", da)
		}
		return nil
	}))
	mustLogin(t, c)
	if e.errOut.String() != "" {
		t.Fatalf("a custom handler replaces the prompt, got %q", e.errOut.String())
	}
}

func TestNautheraBrowserLogin(t *testing.T) {
	t.Parallel()
	for _, issuerPath := range []string{"", "/orgs/acme"} {
		t.Run("issuer path "+issuerPath, func(t *testing.T) {
			t.Parallel()
			e := newNauthera(t, func(c *oauthtest.Config) { c.IssuerPath = issuerPath })
			c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
			tok := mustLogin(t, c)
			if tok.IDToken == "" || tok.RefreshToken == "" {
				t.Fatalf("token set: %v", tok)
			}
			if e.as.CallbackStatus() != http.StatusOK {
				t.Fatalf("loopback page status %d", e.as.CallbackStatus())
			}
			q := e.as.Requests(oauthtest.EndpointAuthorization)[0].Query
			redirect, err := url.Parse(q.Get("redirect_uri"))
			if err != nil || redirect.Hostname() != "127.0.0.1" || redirect.Port() == "" || redirect.Path != "/callback" {
				t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
			}
			if q.Get("code_challenge_method") != "S256" || len(q.Get("state")) < 43 || q.Get("nonce") == "" ||
				q.Get("client_id") != nautheraCLI || q.Get("scope") != "openid offline_access" {
				t.Fatalf("authorization request: %v", q)
			}
			redeem := e.as.Requests(oauthtest.EndpointToken)[0].Form
			if redeem.Get("redirect_uri") != q.Get("redirect_uri") || redeem.Get("code_verifier") == "" {
				t.Fatalf("code redemption: %v", redeem)
			}
			assertNoSecret(t, "output", e.errOut.String()+e.out.String(), redeem.Get("code"), redeem.Get("code_verifier"), tok.AccessToken)
		})
	}
}

func TestNautheraBrowserLoginRefusesMixUp(t *testing.T) {
	t.Parallel()
	cases := map[string]oauthtest.Quirks{
		"wrong iss":   {WrongIss: true},
		"missing iss": {OmitIss: true},
	}
	for name, quirks := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newNauthera(t, func(c *oauthtest.Config) { c.Quirks = quirks })
			c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
			_, err := c.Login(t.Context())
			wantErr(t, err, auth.ErrIssuerMismatch)
			if n := len(e.as.Requests(oauthtest.EndpointToken)); n != 0 {
				t.Fatalf("the code was redeemed (%d token requests) despite the iss mismatch", n)
			}
			if e.as.CallbackStatus() != http.StatusBadRequest {
				t.Fatalf("loopback page status %d, want 400", e.as.CallbackStatus())
			}
		})
	}
}

func TestNautheraBrowserLoginDenied(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, func(c *oauthtest.Config) { c.Consent = func(url.Values) bool { return false } })
	c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
	_, err := c.Login(t.Context())
	wantErr(t, err, auth.ErrAccessDenied)
	if oe := oauthErr(t, err); oe.StatusCode != 0 || oe.Description == "" {
		t.Fatalf("redirect error: %+v", oe)
	}
}

func TestNautheraRefreshRotationAndReuseDetection(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice))
	first := mustLogin(t, e.client)

	// Still valid: no refresh.
	if tok, err := e.client.Token(t.Context()); err != nil || tok.AccessToken != first.AccessToken {
		t.Fatalf("Token before expiry: %v %v", tok, err)
	}
	e.clock.Advance(11 * time.Minute) // nauthera's access tokens live 10 minutes
	second, err := e.client.Token(t.Context())
	if err != nil {
		t.Fatalf("Token after expiry: %v", err)
	}
	if second.AccessToken == first.AccessToken || second.RefreshToken == first.RefreshToken || second.RefreshToken == "" {
		t.Fatal("the refresh did not rotate the tokens")
	}
	if stored, _ := e.client.StoredToken(t.Context()); stored.RefreshToken != second.RefreshToken {
		t.Fatal("the rotated refresh token was not persisted")
	}
	if form := e.as.Requests(oauthtest.EndpointToken)[1].Form; form.Get("grant_type") != "refresh_token" || form.Has("scope") {
		t.Fatalf("refresh request: %v", form)
	}

	// Presenting the spent refresh token again is treated as theft: the
	// server revokes the grant, and the client says to log in again.
	_, err = e.client.Refresh(t.Context(), first)
	wantErr(t, err, auth.ErrLoginRequired, auth.ErrInvalidGrant)
	if !e.as.Revoked(second.RefreshToken) {
		t.Fatal("reuse did not revoke the grant")
	}
	e.clock.Advance(11 * time.Minute)
	_, err = e.client.Token(t.Context())
	wantErr(t, err, auth.ErrLoginRequired)
}

func TestNautheraNoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithScopes("openid"))
	tok := mustLogin(t, e.client)
	if tok.RefreshToken != "" {
		t.Fatal("nauthera issues refresh tokens only with offline_access")
	}
	e.clock.Advance(11 * time.Minute)
	_, err := e.client.Token(t.Context())
	wantErr(t, err, auth.ErrLoginRequired)
	if !strings.Contains(err.Error(), "offline_access") {
		t.Fatalf("the error should say how to get a refresh token: %v", err)
	}
}

func TestNautheraDPoP(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithDPoP())
	tok := mustLogin(t, e.client)
	if tok.TokenType != auth.TokenTypeDPoP || tok.DPoPKey == "" {
		t.Fatalf("token set is not DPoP-bound: %v", tok)
	}
	jkt := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0].Form.Get("dpop_jkt")
	if len(jkt) != 43 {
		t.Fatalf("dpop_jkt = %q, want a SHA-256 thumbprint", jkt)
	}
	// nauthera always wants a nonce: the first poll is refused with
	// use_dpop_nonce and retried with the nonce at once, then succeeds.
	polls := e.as.Requests(oauthtest.EndpointToken)
	if len(polls) != 2 || polls[0].Header.Get("DPoP") == "" || polls[0].Header.Get("DPoP") == polls[1].Header.Get("DPoP") {
		t.Fatalf("want two token requests with distinct proofs, got %d", len(polls))
	}
	if waits := e.clock.Waits(); len(waits) != 1 {
		t.Fatalf("the nonce retry must not wait for the polling interval: waits %v", waits)
	}

	// A second run of the CLI, with an empty nonce cache: the resource
	// server's nonce challenge is answered with one retry.
	next := e.newClient(t, auth.WithFlow(auth.FlowDevice), auth.WithDPoP())
	hc := &http.Client{Transport: next.Transport(e.as.Client().Transport)}
	resp := get(t, hc, e.as.Issuer()+"/userinfo")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "user-1") {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, body)
	}
	ui := e.as.Requests(oauthtest.EndpointUserInfo)
	if len(ui) != 2 || !strings.HasPrefix(ui[1].Header.Get("Authorization"), "DPoP ") {
		t.Fatalf("want a nonce challenge and one DPoP retry, got %d requests", len(ui))
	}

	// The refresh token is bound to the stored key, across runs.
	e.clock.Advance(11 * time.Minute)
	refreshed, err := next.Token(t.Context())
	if err != nil {
		t.Fatalf("refresh with the stored DPoP key: %v", err)
	}
	if refreshed.TokenType != auth.TokenTypeDPoP || refreshed.DPoPKey != tok.DPoPKey {
		t.Fatal("the refreshed token set lost its binding")
	}
}

func TestNautheraDPoPBoundRefreshTokenNeedsItsKey(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithDPoP())
	tok := mustLogin(t, e.client)
	stolen := tok.Clone()
	stolen.DPoPKey = foreignDPoPKey(t)
	_, err := e.client.Refresh(t.Context(), stolen)
	wantErr(t, err, auth.ErrInvalidDPoPProof)
	if e.as.Revoked(tok.RefreshToken) {
		t.Fatal("a refused proof must not spend the refresh token")
	}
	if _, err := e.client.Refresh(t.Context(), tok); err != nil {
		t.Fatalf("refresh with the right key: %v", err)
	}
}

func TestNautheraPushedAuthorizationRequired(t *testing.T) {
	t.Parallel()
	cfg := nautheraConfig(t, "discovery-fapi.json")
	e := newEnv(t, cfg, nautheraPreset())
	c := e.newClient(t, auth.WithDPoP(), auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
	tok := mustLogin(t, c)
	if tok.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("token type %s", tok.TokenType)
	}
	par := e.as.Requests(oauthtest.EndpointPAR)
	if len(par) != 1 {
		t.Fatalf("%d pushed requests, want 1", len(par))
	}
	pushed := par[0]
	if pushed.Header.Get("DPoP") != "" {
		t.Fatal("nauthera binds a pushed request with dpop_jkt, not a DPoP proof")
	}
	for _, p := range []string{"client_id", "code_challenge", "state", "nonce", "redirect_uri", "dpop_jkt", "scope"} {
		if pushed.Form.Get(p) == "" {
			t.Fatalf("pushed request lacks %s: %v", p, pushed.Form)
		}
	}
	q := e.as.Requests(oauthtest.EndpointAuthorization)[0].Query
	if len(q) != 2 || q.Get("client_id") != nautheraCLI || !strings.HasPrefix(q.Get("request_uri"), "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("the browser URL must carry only client_id and request_uri: %v", q)
	}
}

func TestNautheraLogoutRevokesRefreshTokenFirst(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, func(c *oauthtest.Config) { c.RevokeUnavailable = 1 }, auth.WithFlow(auth.FlowDevice))
	tok := mustLogin(t, e.client)
	if err := e.client.Logout(t.Context()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	var hints []string
	for _, r := range e.as.Requests(oauthtest.EndpointRevocation) {
		hints = append(hints, r.Form.Get("token_type_hint"))
		if r.Form.Get("client_id") != nautheraCLI {
			t.Fatalf("revocation without client_id: %v", r.Form)
		}
	}
	// 503 means the token is still live: retried, refresh token first.
	if want := []string{"refresh_token", "refresh_token", "access_token"}; !slices.Equal(hints, want) {
		t.Fatalf("revocations %v, want %v", hints, want)
	}
	if !e.as.Revoked(tok.RefreshToken) || !e.as.Revoked(tok.AccessToken) {
		t.Fatal("tokens still live at the server")
	}
	if _, err := e.client.StoredToken(t.Context()); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Fatalf("token kept locally: %v", err)
	}
}

func TestNautheraTokenExchangeIsUnsupported(t *testing.T) {
	t.Parallel()
	req := auth.ExchangeRequest{SubjectToken: "subject", SubjectTokenType: auth.AccessTokenType}

	// The document does not list the grant: refused before any request.
	e := newNauthera(t, nil)
	_, err := e.client.ExchangeToken(t.Context(), req)
	wantErr(t, err, auth.ErrUnsupportedFlow)
	if n := len(e.as.Requests(oauthtest.EndpointToken)); n != 0 {
		t.Fatalf("%d token requests for an unadvertised grant", n)
	}

	// A document without grant_types_supported: the server's 503 says it.
	e.as.SetMetadata("grant_types_supported", nil)
	c := e.newClient(t, auth.WithClientID(nautheraCLI))
	_, err = c.ExchangeToken(t.Context(), req)
	wantErr(t, err, auth.ErrUnsupportedFlow, auth.ErrTemporarilyUnavailable)
}

func TestNautheraIntrospectionIsForConfidentialClients(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil)
	_, err := e.client.Introspect(t.Context(), "some-token")
	wantErr(t, err, auth.ErrInvalidConfig)
	if n := len(e.as.Requests(oauthtest.EndpointIntrospection)); n != 0 {
		t.Fatalf("a public client sent %d introspection requests", n)
	}

	svc := e.newClient(t, auth.WithClientID(nautheraService), auth.WithClientSecret(nautheraServiceSecret),
		auth.WithFlow(auth.FlowClientCredentials), auth.WithScopes("reports:read"))
	tok := mustLogin(t, svc)
	in, err := svc.Introspect(t.Context(), tok.AccessToken)
	if err != nil || !in.Active || in.ClientID != nautheraService || in.Scope != "reports:read" || in.Expiry.IsZero() {
		t.Fatalf("introspection: %+v %v", in, err)
	}
	if in, err := svc.Introspect(t.Context(), "unknown"); err != nil || in.Active {
		t.Fatalf("unknown token: %+v %v", in, err)
	}
}

func TestNautheraClientCredentialsBasicEncoding(t *testing.T) {
	t.Parallel()
	e := newNauthera(t, nil)
	svc := e.newClient(t, auth.WithClientID(nautheraService), auth.WithClientSecret(nautheraServiceSecret),
		auth.WithFlow(auth.FlowClientCredentials))
	tok, err := svc.Token(t.Context()) // nothing stored yet: obtained and stored
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if tok.RefreshToken != "" || tok.Scope != "" {
		t.Fatalf("token set: %v", tok)
	}
	r := e.as.Requests(oauthtest.EndpointToken)[0]
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") || r.Form.Has("client_secret") || r.Form.Has("client_id") || r.Form.Has("scope") {
		t.Fatalf("client_secret_basic request: %v %v", r.Header.Get("Authorization"), r.Form)
	}
	// Expired: replaced with a new client credentials token, not refreshed.
	e.clock.Advance(11 * time.Minute)
	next, err := svc.Token(t.Context())
	if err != nil || next.AccessToken == tok.AccessToken {
		t.Fatalf("renewal: %v %v", next, err)
	}

	bad := e.newClient(t, auth.WithClientID(nautheraService), auth.WithClientSecret("wrong"), auth.WithFlow(auth.FlowClientCredentials))
	_, err = bad.Login(t.Context())
	wantErr(t, err, auth.ErrInvalidClient)
	assertNoSecret(t, "error", err.Error(), "wrong", nautheraServiceSecret)
}

// TestNautheraRecordedResponses replays the responses in
// testdata/nauthera/responses and checks the library reads each the way
// it is meant.
func TestNautheraRecordedResponses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file   string
		code   string
		status int
		want   error
	}{
		{"token-authorization-pending.json", "authorization_pending", 400, auth.ErrAuthorizationPending},
		{"token-slow-down.json", "slow_down", 400, auth.ErrSlowDown},
		{"token-expired-token.json", "expired_token", 400, auth.ErrExpiredToken},
		{"token-access-denied.json", "access_denied", 400, auth.ErrAccessDenied},
		{"token-invalid-grant-reuse.json", "invalid_grant", 400, auth.ErrInvalidGrant},
		{"token-unauthorized-client.json", "unauthorized_client", 400, auth.ErrUnauthorizedClient},
		{"token-invalid-client.json", "invalid_client", 401, auth.ErrInvalidClient},
		{"token-exchange-unavailable.json", "temporarily_unavailable", 503, auth.ErrTemporarilyUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			e := newNauthera(t, nil)
			e.as.Override(oauthtest.EndpointToken, e.as.Replay(nautheraFixture("responses/"+tc.file)))
			svc := e.newClient(t, auth.WithClientID(nautheraService), auth.WithClientSecret(nautheraServiceSecret),
				auth.WithFlow(auth.FlowClientCredentials))
			_, err := svc.Login(t.Context())
			wantErr(t, err, tc.want)
			oe := oauthErr(t, err)
			if oe.Code != tc.code || oe.StatusCode != tc.status || oe.Description == "" ||
				(oe.URI != "" && !strings.HasPrefix(oe.URI, "https://nauthera.io/runbooks/oauth/")) {
				t.Fatalf("parsed error: %+v", oe)
			}
		})
	}

	t.Run("device authorization", func(t *testing.T) {
		t.Parallel()
		e := newNauthera(t, nil)
		e.as.Override(oauthtest.EndpointDeviceAuthorization, e.as.Replay(nautheraFixture("responses/device-authorization.json")))
		da, err := e.client.StartDeviceAuthorization(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if da.UserCode != "WDJB-MJHT" || da.VerificationURI != e.as.Issuer()+"/device" ||
			da.VerificationURIComplete != e.as.Issuer()+"/device?user_code=WDJB-MJHT" ||
			da.Interval != 5*time.Second || !da.ExpiresAt.Equal(e.clock.Now().Add(900*time.Second)) {
			t.Fatalf("device authorization: %+v", da)
		}
	})

	t.Run("use_dpop_nonce is retried once", func(t *testing.T) {
		t.Parallel()
		e := newNauthera(t, nil)
		e.as.Override(oauthtest.EndpointToken, e.as.Replay(nautheraFixture("responses/token-use-dpop-nonce.json")))
		svc := e.newClient(t, auth.WithClientID(nautheraService), auth.WithClientSecret(nautheraServiceSecret),
			auth.WithFlow(auth.FlowClientCredentials), auth.WithDPoP())
		_, err := svc.Login(t.Context())
		wantErr(t, err, auth.ErrUseDPoPNonce)
		reqs := e.as.Requests(oauthtest.EndpointToken)
		if len(reqs) != 2 {
			t.Fatalf("%d token requests, want the original and one retry", len(reqs))
		}
	})

	t.Run("revocation unavailable", func(t *testing.T) {
		t.Parallel()
		e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice))
		mustLogin(t, e.client)
		e.as.Override(oauthtest.EndpointRevocation, e.as.Replay(nautheraFixture("responses/revoke-unavailable.json")))
		err := e.client.Logout(t.Context())
		wantErr(t, err, auth.ErrRevocationFailed, auth.ErrTemporarilyUnavailable)
		if n := len(e.as.Requests(oauthtest.EndpointRevocation)); n != 6 {
			t.Fatalf("%d revocation requests, want 3 attempts for each of two tokens", n)
		}
		if _, err := e.client.StoredToken(t.Context()); !errors.Is(err, auth.ErrNotLoggedIn) {
			t.Fatal("a failed revocation must still delete the local tokens")
		}
	})

	t.Run("resource server nonce challenge", func(t *testing.T) {
		t.Parallel()
		e := newNauthera(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithDPoP())
		mustLogin(t, e.client)
		e.as.Override(oauthtest.EndpointUserInfo, e.as.Replay(nautheraFixture("responses/userinfo-use-dpop-nonce.json")))
		hc := &http.Client{Transport: e.client.Transport(e.as.Client().Transport)}
		resp := get(t, hc, e.as.Issuer()+"/userinfo")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d", resp.StatusCode)
		}
		ui := e.as.Requests(oauthtest.EndpointUserInfo)
		if len(ui) != 2 || ui[0].Header.Get("DPoP") == ui[1].Header.Get("DPoP") {
			t.Fatalf("want one retry with a new proof, got %d requests", len(ui))
		}
	})
}
