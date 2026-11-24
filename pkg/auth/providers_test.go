package auth_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
)

// Provider quirk tests: each provider's documented deviations, replayed by
// the fake server from a fixture under testdata/providers, against the
// library configured with that provider's preset. They pin down the
// tolerance the library promises, so a refactor cannot lose it.

func providerFixture(t *testing.T, provider, file string) map[string]any {
	t.Helper()
	return oauthtest.LoadJSON(t, filepath.Join("testdata", "providers", provider, file))
}

// slowDownScript is the poll sequence most provider tests use: one
// pending, one slow_down, then approval.
var slowDownScript = []oauthtest.DeviceStep{oauthtest.DevicePending, oauthtest.DeviceSlowDown, oauthtest.DeviceApprove}

func TestGitHub(t *testing.T) {
	t.Parallel()
	const clientID = "Iv1.0123456789abcdef"
	githubConfig := func(t *testing.T) oauthtest.Config {
		t.Helper()
		return oauthtest.Config{
			TLS:             true,
			Metadata:        providerFixture(t, "github", "endpoints.json"),
			Discovery:       oauthtest.DiscoveryNone,
			Clients:         []oauthtest.Client{{ID: clientID}},
			NoIDTokens:      true,
			NoRefreshTokens: true,
			DeviceScript:    slowDownScript,
			VerificationURI: "{{origin}}/login/device",
			Quirks: oauthtest.Quirks{
				DeviceAuthWithoutSecret: true,
				// Device polling errors come back with HTTP 200.
				ErrorStatus:               map[string]int{"*": http.StatusOK},
				TokenType:                 "bearer",
				ScopeSeparator:            ",",
				NoExpiresIn:               true,
				SlowDownInterval:          true,
				NoVerificationURIComplete: true,
			},
		}
	}
	// GitHubEnterprise takes the host; the fake server is one.
	preset := func(e string) []auth.Option {
		return []auth.Option{auth.GitHubEnterprise(e), auth.WithClientID(clientID), auth.WithScopes("repo", "read:org")}
	}

	for _, form := range []bool{false, true} {
		name := "JSON responses"
		if form {
			name = "form-encoded responses"
		}
		t.Run("OAuth app device flow, "+name, func(t *testing.T) {
			t.Parallel()
			cfg := githubConfig(t)
			cfg.Quirks.FormEncoded = form
			e := newEnv(t, cfg, nil)
			c := e.newClient(t, append(preset(e.as.URL), auth.WithFlow(auth.FlowDevice))...)
			tok := mustLogin(t, c)
			if tok.TokenType != auth.TokenTypeBearer || tok.Scope != "repo read:org" || !tok.Expiry.IsZero() ||
				tok.RefreshToken != "" || tok.IDToken != "" {
				t.Fatalf("token set: %v", tok)
			}
			// slow_down carries the new interval (10 s); it is honored.
			if got, want := e.clock.Waits(), []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}; !slices.Equal(got, want) {
				t.Fatalf("waits %v, want %v", got, want)
			}
			if n := len(e.as.Requests(oauthtest.EndpointDiscovery)); n != 0 {
				t.Fatalf("GitHub has no discovery, yet %d discovery requests were made", n)
			}
			for _, r := range append(e.as.Requests(oauthtest.EndpointDeviceAuthorization), e.as.Requests(oauthtest.EndpointToken)...) {
				if r.Header.Get("Accept") != "application/json" {
					t.Fatalf("request without Accept: application/json: %v", r.Header)
				}
			}
			// A token without an expiry never expires locally.
			e.clock.Advance(365 * 24 * time.Hour)
			if again, err := c.Token(t.Context()); err != nil || again.AccessToken != tok.AccessToken {
				t.Fatalf("non-expiring token: %v %v", again, err)
			}
		})
	}

	t.Run("GitHub App with expiring tokens", func(t *testing.T) {
		t.Parallel()
		cfg := githubConfig(t)
		cfg.Clients = []oauthtest.Client{{ID: clientID, Secret: "github-app-secret"}}
		cfg.NoRefreshTokens = false
		cfg.Quirks.NoExpiresIn = false
		cfg.AccessTokenTTL = 8 * time.Hour
		cfg.Quirks.ExtraTokenFields = map[string]any{"refresh_token_expires_in": 15897600}
		cfg.DeviceScript = nil
		e := newEnv(t, cfg, nil)
		c := e.newClient(t, append(preset(e.as.URL), auth.WithClientSecret("github-app-secret"), auth.WithFlow(auth.FlowDevice))...)
		tok := mustLogin(t, c)
		if tok.RefreshToken == "" || tok.Expiry.IsZero() || tok.Extra["refresh_token_expires_in"] == nil {
			t.Fatalf("token set: %v (extra %v)", tok, tok.Extra)
		}
		// The secret goes in the body, and never to the device endpoint.
		da := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0]
		if da.Form.Has("client_secret") || da.Header.Get("Authorization") != "" {
			t.Fatalf("device authorization sent the secret: %v", da.Form)
		}
		poll := e.as.Requests(oauthtest.EndpointToken)[0]
		if poll.Form.Get("client_secret") != "github-app-secret" || poll.Header.Get("Authorization") != "" {
			t.Fatalf("token request: %v %v", poll.Form, poll.Header)
		}
		e.clock.Advance(9 * time.Hour)
		next, err := c.Token(t.Context())
		if err != nil || next.RefreshToken == tok.RefreshToken {
			t.Fatalf("refresh: %v %v", next, err)
		}
	})

	t.Run("non-RFC device error is terminal", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, githubConfig(t), nil)
		e.as.Override(oauthtest.EndpointToken, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"device_flow_disabled","error_description":"Device Flow must be explicitly enabled for this App","error_uri":"https://docs.github.com"}`))
		})
		c := e.newClient(t, append(preset(e.as.URL), auth.WithFlow(auth.FlowDevice))...)
		_, err := c.Login(t.Context())
		if oe := oauthErr(t, err); oe.Code != "device_flow_disabled" || oe.StatusCode != http.StatusOK {
			t.Fatalf("error: %+v", oe)
		}
		if n := len(e.as.Requests(oauthtest.EndpointToken)); n != 1 {
			t.Fatalf("polled %d times after a terminal error", n)
		}
	})
}

func TestGoogle(t *testing.T) {
	t.Parallel()
	const (
		clientID = "1234567890-abc.apps.googleusercontent.com"
		secret   = "GOCSPX-installed-app-secret"
	)
	googleConfig := func(t *testing.T) oauthtest.Config {
		t.Helper()
		return oauthtest.Config{
			TLS:        true,
			Metadata:   providerFixture(t, "google", "discovery.json"),
			Discovery:  oauthtest.DiscoveryOIDC,
			SigningAlg: "RS256",
			Clients: []oauthtest.Client{{
				ID: clientID, Secret: secret, RedirectURIs: []string{"http://127.0.0.1/callback"},
			}},
			DeviceScript:   slowDownScript,
			AccessTokenTTL: time.Hour,
			// Google does not rotate refresh tokens and omits them on refresh.
			RefreshPolicy: oauthtest.RefreshOmit,
			// The legacy issuer spelling still appears in ID tokens.
			IDTokenIssuer: "accounts.google.com",
			Quirks: oauthtest.Quirks{
				DeviceAuthWithoutSecret:   true,
				VerificationURL:           true,
				NoVerificationURIComplete: true,
				OmitIss:                   true,
				ErrorStatus:               map[string]int{"authorization_pending": 428, "slow_down": 403, "access_denied": 403},
			},
		}
	}
	preset := []auth.Option{auth.Google(), auth.WithClientID(clientID), auth.WithClientSecret(secret)}

	t.Run("device flow", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, googleConfig(t), preset, auth.WithFlow(auth.FlowDevice), auth.WithScopes("openid", "email"))
		tok := mustLogin(t, e.client)
		if tok.IDToken == "" || tok.RefreshToken == "" {
			t.Fatalf("token set: %v", tok)
		}
		if !strings.Contains(e.errOut.String(), e.as.URL+"/device") {
			t.Fatalf("verification_url was not shown:\n%s", e.errOut.String())
		}
		if got, want := e.clock.Waits(), []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}; !slices.Equal(got, want) {
			t.Fatalf("waits %v, want %v (428 pending, 403 slow_down)", got, want)
		}
		da := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0]
		poll := e.as.Requests(oauthtest.EndpointToken)[0]
		if da.Form.Has("client_secret") || poll.Form.Get("client_secret") != secret || poll.Header.Get("Authorization") != "" {
			t.Fatal("Google wants the secret in the token request body only")
		}

		e.clock.Advance(61 * time.Minute)
		next, err := e.client.Token(t.Context())
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if next.RefreshToken != tok.RefreshToken {
			t.Fatal("the refresh token must be kept when the response has none")
		}
	})

	t.Run("browser flow without iss", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, googleConfig(t), preset)
		c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
		mustLogin(t, c)
		// plain is advertised, S256 is still the only method sent.
		if m := e.as.Requests(oauthtest.EndpointAuthorization)[0].Query.Get("code_challenge_method"); m != "S256" {
			t.Fatalf("code_challenge_method = %q", m)
		}
	})

	t.Run("denied", func(t *testing.T) {
		t.Parallel()
		cfg := googleConfig(t)
		cfg.DeviceScript = []oauthtest.DeviceStep{oauthtest.DeviceDeny}
		e := newEnv(t, cfg, preset, auth.WithFlow(auth.FlowDevice))
		_, err := e.client.Login(t.Context())
		wantErr(t, err, auth.ErrAccessDenied)
		if oe := oauthErr(t, err); oe.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", oe.StatusCode)
		}
	})
}

func TestEntraID(t *testing.T) {
	t.Parallel()
	const (
		clientID = "11111111-2222-3333-4444-555555555555"
		tenant   = "9188040d-6c67-4c5b-b112-36a304b66dad"
	)
	entraConfig := func(t *testing.T) oauthtest.Config {
		t.Helper()
		return oauthtest.Config{
			TLS:          true,
			IssuerPath:   "/common/v2.0",
			Metadata:     providerFixture(t, "entra", "discovery.json"),
			Discovery:    oauthtest.DiscoveryOIDC,
			SigningAlg:   "RS256",
			Clients:      []oauthtest.Client{{ID: clientID, RedirectURIs: []string{"http://127.0.0.1/callback"}}},
			RefreshScope: "offline_access",
			// Multi-tenant metadata names {tenantid}; the ID token names
			// the user's tenant, and its tid claim says which.
			IDTokenIssuer:  "{{origin}}/" + tenant + "/v2.0",
			IDTokenClaims:  map[string]any{"tid": tenant, "preferred_username": "user@contoso.example"},
			AccessTokenTTL: 3599 * time.Second,
			DeviceScript:   []oauthtest.DeviceStep{oauthtest.DevicePending, oauthtest.DeviceApprove},
			Quirks:         oauthtest.Quirks{ExtraTokenFields: map[string]any{"ext_expires_in": 3599}},
		}
	}
	preset := []auth.Option{auth.EntraID("common"), auth.WithClientID(clientID)}

	t.Run("v2 device flow", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, entraConfig(t), preset, auth.WithFlow(auth.FlowDevice))
		tok := mustLogin(t, e.client)
		if tok.IDToken == "" || tok.RefreshToken == "" || tok.Extra["ext_expires_in"] == nil {
			t.Fatalf("token set: %v (extra %v)", tok, tok.Extra)
		}
		if got := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0].Form.Get("scope"); got != "openid profile offline_access" {
			t.Fatalf("scope = %q", got)
		}
		st, err := e.client.Status(t.Context())
		if err != nil || st.Name != "user@contoso.example" {
			t.Fatalf("status: %+v %v", st, err)
		}
	})

	t.Run("v1-style strings and verification_url", func(t *testing.T) {
		t.Parallel()
		cfg := entraConfig(t)
		cfg.Quirks.StringNumbers = true
		cfg.Quirks.VerificationURL = true
		cfg.DeviceInterval = 3
		e := newEnv(t, cfg, preset, auth.WithFlow(auth.FlowDevice))
		tok := mustLogin(t, e.client)
		if !tok.Expiry.Equal(e.clock.Now().Add(3599 * time.Second)) {
			t.Fatalf("expires_in \"3599\" gave expiry %v (now %v)", tok.Expiry, e.clock.Now())
		}
		if w := e.clock.Waits(); len(w) == 0 || w[0] != 3*time.Second {
			t.Fatalf("interval \"3\" was not honored: %v", w)
		}
	})

	t.Run("browser flow without advertised PKCE", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, entraConfig(t), preset)
		c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
		mustLogin(t, c)
	})

	t.Run("tid that does not match iss", func(t *testing.T) {
		t.Parallel()
		cfg := entraConfig(t)
		cfg.IDTokenClaims = map[string]any{"tid": "00000000-0000-0000-0000-000000000000"}
		e := newEnv(t, cfg, preset, auth.WithFlow(auth.FlowDevice))
		_, err := e.client.Login(t.Context())
		wantErr(t, err, auth.ErrInvalidIDToken, auth.ErrIssuerMismatch)
	})

	// For "consumers" and for a verified domain, Entra's document names the
	// tenant's GUID instead of the name the client was configured with.
	for _, name := range []string{"consumers", "contoso.onmicrosoft.com"} {
		t.Run("tenant "+name+" resolves to its GUID issuer", func(t *testing.T) {
			t.Parallel()
			cfg := entraConfig(t)
			cfg.IssuerPath = "/" + name + "/v2.0"
			cfg.Metadata["issuer"] = "{{origin}}/" + tenant + "/v2.0"
			e := newEnv(t, cfg, []auth.Option{auth.EntraID(name), auth.WithClientID(clientID)}, auth.WithFlow(auth.FlowDevice))
			md, err := e.client.Metadata(t.Context())
			if err != nil {
				t.Fatalf("Metadata: %v", err)
			}
			if want := e.as.URL + "/" + tenant + "/v2.0"; md.Issuer != want {
				t.Fatalf("issuer %q, want the document's %q", md.Issuer, want)
			}
			mustLogin(t, e.client)
			// Tokens stay stored under the issuer the client was configured with.
			if got := e.client.StorageKey().Issuer; got != e.as.Issuer() {
				t.Fatalf("storage issuer %q", got)
			}
		})
	}

	t.Run("a GUID issuer for another tenant name is refused without the preset", func(t *testing.T) {
		t.Parallel()
		cfg := entraConfig(t)
		cfg.IssuerPath = "/consumers/v2.0"
		cfg.Metadata["issuer"] = "{{origin}}/" + tenant + "/v2.0"
		e := newEnv(t, cfg, []auth.Option{auth.WithClientID(clientID)})
		_, err := e.client.Metadata(t.Context())
		wantErr(t, err, auth.ErrIssuerMismatch)
	})

	t.Run("the template is refused without the preset", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, entraConfig(t), []auth.Option{auth.WithClientID(clientID)})
		_, err := e.client.Metadata(t.Context())
		wantErr(t, err, auth.ErrIssuerMismatch)
	})
}

func TestAuth0(t *testing.T) {
	t.Parallel()
	const audience = "https://api.example.com"
	cfg := func(t *testing.T) oauthtest.Config {
		t.Helper()
		return oauthtest.Config{
			TLS:          true,
			IssuerPath:   "/", // Auth0's issuer has a trailing slash
			Metadata:     providerFixture(t, "auth0", "discovery.json"),
			Discovery:    oauthtest.DiscoveryOIDC,
			SigningAlg:   "RS256",
			Clients:      []oauthtest.Client{{ID: "auth0-native-cli", RedirectURIs: []string{"http://127.0.0.1/callback"}}},
			RefreshScope: "offline_access",
			DeviceScript: slowDownScript,
			Quirks: oauthtest.Quirks{ErrorStatus: map[string]int{
				"authorization_pending": 403, "slow_down": 429, "expired_token": 403, "access_denied": 403,
			}},
		}
	}

	t.Run("device flow with audience", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, cfg(t), nil)
		c := e.newClient(t, auth.Auth0(e.as.URL, audience), auth.WithIssuer(e.as.Issuer()), auth.WithClientID("auth0-native-cli"),
			auth.WithFlow(auth.FlowDevice))
		tok := mustLogin(t, c)
		if tok.RefreshToken == "" || tok.IDToken == "" {
			t.Fatalf("token set: %v", tok)
		}
		if got := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0].Form.Get("audience"); got != audience {
			t.Fatalf("audience = %q", got)
		}
		if got := c.StorageKey().Audience; got != audience {
			t.Fatalf("tokens are not stored per audience: %q", got)
		}
		if got, want := e.clock.Waits(), []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}; !slices.Equal(got, want) {
			t.Fatalf("waits %v, want %v (403 pending, 429 slow_down)", got, want)
		}
		if n := len(e.as.Requests(oauthtest.EndpointDiscovery)); n != 1 {
			t.Fatalf("%d discovery requests; the OIDC location with the trailing slash folded should be found first", n)
		}
	})

	t.Run("expired with 403", func(t *testing.T) {
		t.Parallel()
		c := cfg(t)
		c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DevicePending, oauthtest.DeviceExpire}
		e := newEnv(t, c, nil)
		cl := e.newClient(t, auth.Auth0(e.as.URL, audience), auth.WithIssuer(e.as.Issuer()), auth.WithClientID("auth0-native-cli"),
			auth.WithFlow(auth.FlowDevice))
		_, err := cl.Login(t.Context())
		wantErr(t, err, auth.ErrExpiredToken)
	})
}

func TestKeycloak(t *testing.T) {
	t.Parallel()
	cfg := oauthtest.Config{
		TLS:           true,
		IssuerPath:    "/realms/acme",
		Clients:       []oauthtest.Client{{ID: "kc-cli", RedirectURIs: []string{"http://127.0.0.1/callback"}}},
		RefreshPolicy: oauthtest.RefreshReuse,
		DPoP:          oauthtest.DPoPPolicy{Enabled: true},
		Quirks: oauthtest.Quirks{ExtraTokenFields: map[string]any{
			"refresh_expires_in": 1800, "not-before-policy": 0, "session_state": "6f1e2a0c-redacted",
		}},
	}
	cfg.Metadata = providerFixture(t, "keycloak", "discovery.json")
	e := newEnv(t, cfg, []auth.Option{auth.WithClientID("kc-cli")})
	c := e.newClient(t, auth.Keycloak(e.as.URL, "acme"), auth.WithIssuer(e.as.Issuer()), auth.WithClientID("kc-cli"),
		auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser),
		auth.WithDPoPAuto(), auth.WithPAR(auth.PARIfAvailable))
	tok := mustLogin(t, c)
	if tok.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("DPoP is advertised, so WithDPoPAuto should bind the token: %s", tok.TokenType)
	}
	if tok.Extra["refresh_expires_in"] == nil || tok.Extra["session_state"] == nil || tok.Extra["not-before-policy"] == nil {
		t.Fatalf("extra members lost: %v", tok.Extra)
	}
	if n := len(e.as.Requests(oauthtest.EndpointPAR)); n != 1 {
		t.Fatalf("%d pushed requests with PARIfAvailable", n)
	}
	if got := e.as.Requests(oauthtest.EndpointAuthorization)[0].Query.Get("scope"); got != "" {
		t.Fatalf("a pushed request's parameters leaked into the browser URL: scope=%q", got)
	}
	if got := e.as.Requests(oauthtest.EndpointPAR)[0].Form.Get("scope"); got != "openid profile" {
		t.Fatalf("Keycloak preset scope = %q (no offline_access)", got)
	}
	e.clock.Advance(11 * time.Minute)
	next, err := c.Token(t.Context())
	if err != nil || next.RefreshToken != tok.RefreshToken {
		t.Fatalf("a non-rotating refresh must keep the refresh token: %v %v", next, err)
	}
}

func TestOkta(t *testing.T) {
	t.Parallel()
	cfg := oauthtest.Config{
		TLS:           true,
		IssuerPath:    "/oauth2/default",
		SigningAlg:    "RS256",
		Clients:       []oauthtest.Client{{ID: "0oa-native-cli"}},
		RefreshScope:  "offline_access",
		DPoP:          oauthtest.DPoPPolicy{Enabled: true, RequireNonce: true},
		TokenExchange: true,
	}
	cfg.Metadata = providerFixture(t, "okta", "discovery.json")
	e := newEnv(t, cfg, nil)
	c := e.newClient(t, auth.Okta(e.as.Issuer()), auth.WithClientID("0oa-native-cli"), auth.WithFlow(auth.FlowDevice), auth.WithDPoP())
	tok := mustLogin(t, c)
	if tok.TokenType != auth.TokenTypeDPoP || tok.RefreshToken == "" {
		t.Fatalf("token set: %v", tok)
	}
	// Okta, like nauthera, asks for a nonce on the first proof.
	reqs := e.as.Requests(oauthtest.EndpointToken)
	if len(reqs) != 2 {
		t.Fatalf("%d token requests, want the nonce round trip", len(reqs))
	}

	// Okta advertises token exchange: trade the CLI's token for one.
	res, err := c.ExchangeToken(t.Context(), auth.ExchangeRequest{Audience: []string{"api://reports"}})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if res.IssuedTokenType != auth.AccessTokenType || res.Token.AccessToken == tok.AccessToken || res.Token.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("exchange result: %+v %v", res, res.Token)
	}
	ex := e.as.Requests(oauthtest.EndpointToken)
	last := ex[len(ex)-1].Form
	if last.Get("subject_token") != tok.AccessToken || last.Get("subject_token_type") != string(auth.AccessTokenType) || last.Get("audience") != "api://reports" {
		t.Fatalf("exchange request: %v", last)
	}

	res, err = c.ExchangeToken(t.Context(), auth.ExchangeRequest{RequestedTokenType: auth.JWTTokenType})
	if err != nil || res.Token.TokenType != auth.TokenTypeNA || res.IssuedTokenType != auth.JWTTokenType {
		t.Fatalf("N_A exchange: %+v %v", res, err)
	}
}

func TestGitLab(t *testing.T) {
	t.Parallel()
	cfg := oauthtest.Config{
		TLS:          true,
		Clients:      []oauthtest.Client{{ID: "gitlab-app"}},
		Discovery:    oauthtest.DiscoveryOIDC,
		SigningAlg:   "RS256",
		Unadvertised: map[oauthtest.Endpoint]string{oauthtest.EndpointDeviceAuthorization: "{{origin}}/oauth/authorize_device"},
		Quirks:       oauthtest.Quirks{ExtraTokenFields: map[string]any{"created_at": 1735689600}},
	}
	cfg.Metadata = providerFixture(t, "gitlab", "discovery.json")
	e := newEnv(t, cfg, nil)
	c := e.newClient(t, auth.GitLab(e.as.URL), auth.WithClientID("gitlab-app"), auth.WithFlow(auth.FlowDevice))
	tok := mustLogin(t, c)
	if tok.RefreshToken == "" || tok.Extra["created_at"] == nil {
		t.Fatalf("token set: %v", tok)
	}
}

func TestProviderWithoutRevocation(t *testing.T) {
	t.Parallel()
	// Dex publishes no revocation endpoint: logout is local only, and not
	// an error.
	e := newEnv(t, oauthtest.Config{}, []auth.Option{auth.Dex("https://dex.example.com"), auth.WithClientID(oauthtest.DefaultClientID)},
		auth.WithFlow(auth.FlowDevice))
	e.as.SetMetadata("revocation_endpoint", nil)
	mustLogin(t, e.client)
	if err := e.client.Logout(t.Context()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if n := len(e.as.Requests(oauthtest.EndpointRevocation)); n != 0 {
		t.Fatalf("%d revocation requests", n)
	}
	if err := e.client.Revoke(t.Context(), "x", "access_token"); err == nil {
		t.Fatal("Revoke without an endpoint must fail")
	}
}

// TestFixturesAreValidMetadata keeps the fixtures parseable as metadata.
func TestFixturesAreValidMetadata(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("testdata", "*", "*", "discovery.json"))
	if err != nil {
		t.Fatal(err)
	}
	nauthera, _ := filepath.Glob(filepath.Join("testdata", "nauthera", "discovery*.json"))
	for _, f := range append(files, nauthera...) {
		m := oauthtest.LoadJSON(t, f)
		b, _ := json.Marshal(m)
		var md auth.Metadata
		if err := json.Unmarshal(b, &md); err != nil || md.Issuer == "" || md.TokenEndpoint == "" {
			t.Errorf("%s: %v %+v", f, err, md)
		}
	}
}
