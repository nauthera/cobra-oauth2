package auth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// Options that change what goes over the wire, checked against the fake
// server rather than by inspecting the configuration.

func plainEnv(t *testing.T, mutate func(*oauthtest.Config), opts ...auth.Option) *env {
	t.Helper()
	cfg := oauthtest.Config{}
	if mutate != nil {
		mutate(&cfg)
	}
	return newEnv(t, cfg, []auth.Option{auth.WithClientID(oauthtest.DefaultClientID)}, opts...)
}

func TestWithDiscoveryURL(t *testing.T) {
	t.Parallel()
	for _, mode := range []oauthtest.DiscoveryMode{oauthtest.DiscoveryOIDC, oauthtest.DiscoveryRFC8414} {
		t.Run(strconv.Itoa(int(mode)), func(t *testing.T) {
			t.Parallel()
			as := oauthtest.New(t, oauthtest.Config{IssuerPath: "/tenants/a", Discovery: mode})
			u, _ := url.Parse(as.Issuer())
			doc := as.Issuer() + "/.well-known/openid-configuration"
			if mode == oauthtest.DiscoveryRFC8414 {
				doc = as.URL + "/.well-known/oauth-authorization-server" + u.Path
			}
			c, err := auth.NewClient(auth.WithDiscoveryURL(doc), auth.WithClientID("c"),
				auth.WithHTTPClient(as.Client()), auth.WithStorage(storage.NewMemory()))
			if err != nil {
				t.Fatal(err)
			}
			if c.Issuer() != as.Issuer() {
				t.Fatalf("issuer derived from %s = %q, want %q", doc, c.Issuer(), as.Issuer())
			}
			md, err := c.Metadata(t.Context())
			if err != nil || md.Issuer != as.Issuer() {
				t.Fatalf("Metadata: %+v %v", md, err)
			}
			if got := as.Requests(oauthtest.EndpointDiscovery); len(got) != 1 {
				t.Fatalf("%d discovery requests, want exactly the configured URL", len(got))
			}
		})
	}

	t.Run("without a well-known suffix", func(t *testing.T) {
		t.Parallel()
		c, err := auth.NewClient(auth.WithDiscoveryURL("https://as.example/metadata.json"), auth.WithClientID("c"),
			auth.WithStorage(storage.NewMemory()))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Metadata(t.Context())
		wantErr(t, err, auth.ErrDiscovery)
		if c.Issuer() != "https://as.example/metadata.json" {
			t.Fatalf("Issuer() = %q", c.Issuer())
		}
	})
}

func TestWithoutDiscovery(t *testing.T) {
	t.Parallel()
	clock := oauthtest.NewClock(time.Time{})
	as := oauthtest.New(t, oauthtest.Config{Discovery: oauthtest.DiscoveryNone, Now: clock.Now})
	base := as.Issuer()
	store := storage.NewMemory()
	c, err := auth.NewClient(
		auth.WithIssuer(base), auth.WithoutDiscovery(), auth.WithClientID(oauthtest.DefaultClientID),
		auth.WithEndpoints(auth.Endpoints{Token: base + "/token", Revocation: base + "/revoke"}),
		auth.WithDeviceAuthorizationEndpoint(base+"/device_authorization"),
		auth.WithAuthorizationEndpoint(base+"/authorize"),
		auth.WithJWKSURL(base+"/jwks"),
		auth.WithIntrospectionEndpoint(base+"/introspect"),
		auth.WithEndSessionEndpoint(base+"/end_session"),
		auth.WithPushedAuthorizationEndpoint(base+"/par"),
		auth.WithFlow(auth.FlowDevice), auth.WithHTTPClient(as.Client()), auth.WithStorage(store), auth.WithClock(clock),
	)
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.Issuer != base || md.JWKSURI != base+"/jwks" || md.IntrospectionEndpoint == "" || md.EndSessionEndpoint == "" ||
		md.PushedAuthorizationRequestEndpoint == "" || md.AuthorizationEndpoint == "" {
		t.Fatalf("metadata from configuration: %+v", md)
	}
	tok := mustLogin(t, c)
	if tok.IDToken == "" {
		t.Fatal("expected an ID token, verified with the configured JWKS URL")
	}
	if err := c.Logout(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(as.Requests(oauthtest.EndpointDiscovery)); n != 0 {
		t.Fatalf("%d discovery requests with discovery off", n)
	}

	// Without a token endpoint, nothing works.
	c2, err := auth.NewClient(auth.WithIssuer(base), auth.WithoutDiscovery(), auth.WithClientID("c"), auth.WithStorage(store))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Metadata(t.Context())
	wantErr(t, err, auth.ErrInvalidConfig)
}

func TestWithTokenAndAuthParams(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, nil, auth.WithFlow(auth.FlowDevice),
		auth.WithTokenParam("tenant", "acme"), auth.WithTokenParam("grant_type", "password"),
		auth.WithAuthParam("prompt", "consent"), auth.WithAuthParam("scope", "admin"))
	mustLogin(t, e.client)
	poll := e.as.Requests(oauthtest.EndpointToken)[0].Form
	if poll.Get("tenant") != "acme" || poll.Get("grant_type") != string(auth.GrantDeviceCode) {
		t.Fatalf("token params: %v (a configured parameter must not override the grant's own)", poll)
	}
	da := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0].Form
	if da.Get("prompt") != "consent" || da.Get("scope") != "openid offline_access" {
		t.Fatalf("auth params: %v", da)
	}
}

func TestWithRedirectPortAndPath(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	e := plainEnv(t, func(c *oauthtest.Config) {
		c.Clients = []oauthtest.Client{{ID: oauthtest.DefaultClientID, RedirectURIs: []string{"http://127.0.0.1/oauth/done"}}}
	})
	c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser),
		auth.WithRedirectPort(port), auth.WithRedirectPath("/oauth/done"))
	mustLogin(t, c)
	got := e.as.Requests(oauthtest.EndpointAuthorization)[0].Query.Get("redirect_uri")
	if want := "http://127.0.0.1:" + strconv.Itoa(port) + "/oauth/done"; got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
}

func TestWithRevokeOnLogoutFalse(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithRevokeOnLogout(false))
	tok := mustLogin(t, e.client)
	if err := e.client.Logout(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.as.Requests(oauthtest.EndpointRevocation)); n != 0 || e.as.Revoked(tok.RefreshToken) {
		t.Fatalf("%d revocation requests with revocation off", n)
	}
	if _, err := e.client.StoredToken(t.Context()); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Fatal("logout must still delete the local tokens")
	}
}

func TestIDTokenValidationOptions(t *testing.T) {
	t.Parallel()
	future := oauthtest.DefaultStart.Add(90 * time.Second).Unix()
	cases := []struct {
		name   string
		claims map[string]any
		opts   []auth.Option
		ok     bool
	}{
		{"issued 90 s ahead, default 60 s skew", map[string]any{"iat": future}, nil, false},
		{"issued 90 s ahead, 2 min skew", map[string]any{"iat": future}, []auth.Option{auth.WithClockSkew(2 * time.Minute)}, true},
		{"foreign issuer", map[string]any{"iss": "https://other.example"}, nil, false},
		{"foreign issuer, validation off", map[string]any{"iss": "https://other.example"}, []auth.Option{auth.WithIDTokenValidation(false)}, true},
		{"another audience", map[string]any{"aud": "someone-else"}, nil, false},
		{"several audiences without azp", map[string]any{"aud": []any{oauthtest.DefaultClientID, "x"}}, nil, false},
		{"several audiences with azp", map[string]any{"aud": []any{oauthtest.DefaultClientID, "x"}, "azp": oauthtest.DefaultClientID}, nil, true},
		{"expired", map[string]any{"exp": oauthtest.DefaultStart.Add(-2 * time.Minute).Unix()}, nil, false},
		{"no subject", map[string]any{"sub": ""}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := plainEnv(t, func(c *oauthtest.Config) { c.IDTokenClaims = tc.claims },
				append([]auth.Option{auth.WithFlow(auth.FlowDevice)}, tc.opts...)...)
			_, err := e.client.Login(t.Context())
			if tc.ok && err != nil {
				t.Fatalf("Login: %v", err)
			}
			if !tc.ok {
				wantErr(t, err, auth.ErrInvalidIDToken)
			}
		})
	}
}

func TestWithExpirySkew(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		skew    time.Duration
		refresh bool
	}{{0, false}, {2 * time.Minute, true}} {
		t.Run(tc.skew.String(), func(t *testing.T) {
			t.Parallel()
			e := plainEnv(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithExpirySkew(tc.skew))
			first := mustLogin(t, e.client)
			e.clock.Advance(9 * time.Minute) // one minute before expiry
			tok, err := e.client.Token(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if refreshed := tok.AccessToken != first.AccessToken; refreshed != tc.refresh {
				t.Fatalf("refreshed = %v, want %v", refreshed, tc.refresh)
			}
		})
	}
}

// lockedBuffer collects log output from concurrent handlers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestWithLoggerNeverLogsSecrets(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := plainEnv(t, func(c *oauthtest.Config) {
		c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DeviceSlowDown, oauthtest.DeviceApprove}
		c.Clients = []oauthtest.Client{{ID: oauthtest.DefaultClientID, Secret: "logger-test-secret"}}
	}, auth.WithFlow(auth.FlowDevice), auth.WithLogger(logger), auth.WithClientSecret("logger-test-secret"), auth.WithDPoPAuto())
	tok := mustLogin(t, e.client)
	e.clock.Advance(11 * time.Minute)
	next, err := e.client.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("client", "client", e.client)
	out := logs.String()
	for _, want := range []string{"discovered authorization server metadata", "slow_down", "refreshed access token"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logs lack %q:\n%s", want, out)
		}
	}
	deviceCode := e.as.Requests(oauthtest.EndpointToken)[0].Form.Get("device_code")
	assertNoSecret(t, "logs", out, tok.AccessToken, tok.RefreshToken, tok.IDToken, next.AccessToken, next.RefreshToken,
		deviceCode, "logger-test-secret")
	assertNoSecret(t, "Client.String", e.client.String(), "logger-test-secret")
}

func TestWithEndpointMiddleware(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		order []string
	)
	record := func(name string) auth.EndpointMiddleware {
		return func(next auth.EndpointHandler) auth.EndpointHandler {
			return func(ctx context.Context, req *auth.EndpointRequest) (*auth.EndpointResponse, error) {
				mu.Lock()
				order = append(order, name+":"+string(req.Kind))
				mu.Unlock()
				req.Header.Set("X-Trace-"+name, "1")
				resp, err := next(ctx, req)
				if err == nil && resp.StatusCode == 0 {
					t.Error("middleware saw a response without a status")
				}
				return resp, err
			}
		}
	}
	e := plainEnv(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithEndpointMiddleware(record("outer"), record("inner")),
		auth.WithUserAgent("mycli/1.2.3"))
	mustLogin(t, e.client)
	if err := e.client.Logout(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"outer:device_authorization", "inner:device_authorization", "outer:token", "inner:token",
		"outer:revocation", "inner:revocation", "outer:revocation", "inner:revocation",
	}
	if !slices.Equal(order, want) {
		t.Fatalf("middleware order %v, want %v", order, want)
	}
	r := e.as.Requests(oauthtest.EndpointToken)[0]
	if r.Header.Get("X-Trace-Outer") != "1" || r.Header.Get("X-Trace-Inner") != "1" || r.Header.Get("User-Agent") != "mycli/1.2.3" {
		t.Fatalf("headers: %v", r.Header)
	}
	if ua := e.as.Requests(oauthtest.EndpointDiscovery)[0].Header.Get("User-Agent"); ua != "mycli/1.2.3" {
		t.Fatalf("discovery User-Agent = %q", ua)
	}
}

func TestDefaultUserAgentNamesTheApp(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, nil, auth.WithAppName("mycli"))
	if _, err := e.client.Metadata(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ua := e.as.Requests(oauthtest.EndpointDiscovery)[0].Header.Get("User-Agent"); ua != "mycli cobra-oauth2" {
		t.Fatalf("User-Agent = %q", ua)
	}
}

// basicAuthenticator is a custom ClientAuthenticator, standing in for mTLS
// or a key in a hardware token.
type basicAuthenticator struct{ id, secret string }

func (basicAuthenticator) Method() auth.ClientAuthMethod { return "tls_client_auth" }

func (b basicAuthenticator) Authenticate(_ context.Context, req *auth.EndpointRequest) error {
	req.Header.Set("Authorization", "Basic "+basic(b.id, b.secret))
	req.Header.Set("X-Custom-Auth", req.URL)
	return nil
}

func basic(id, secret string) string {
	r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	r.SetBasicAuth(id, secret)
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
}

func TestWithClientAuthenticator(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, func(c *oauthtest.Config) {
		c.Clients = []oauthtest.Client{{ID: "svc", Secret: "hsm-held"}}
	})
	c := e.newClient(t, auth.WithClientID("svc"), auth.WithClientAuthenticator(basicAuthenticator{"svc", "hsm-held"}),
		auth.WithFlow(auth.FlowClientCredentials))
	tok := mustLogin(t, c)
	r := e.as.Requests(oauthtest.EndpointToken)[0]
	if r.Header.Get("X-Custom-Auth") != e.as.Issuer()+"/token" || r.Form.Has("client_secret") {
		t.Fatalf("custom authentication not applied: %v %v", r.Header, r.Form)
	}
	// A custom authenticator makes the client confidential.
	if in, err := c.Introspect(t.Context(), tok.AccessToken); err != nil || !in.Active {
		t.Fatalf("Introspect: %+v %v", in, err)
	}
}

func TestBrowserLoginTimeout(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, nil)
	c := e.newClient(t, auth.WithFlow(auth.FlowBrowser), auth.WithLoginTimeout(50*time.Millisecond))
	_, err := c.Login(t.Context())
	wantErr(t, err, context.DeadlineExceeded)
	if !strings.Contains(e.errOut.String(), "Open this URL in a browser") {
		t.Fatalf("without a browser the URL must be printed:\n%s", e.errOut.String())
	}
}

func TestLoginContextCanceled(t *testing.T) {
	t.Parallel()
	e := plainEnv(t, func(c *oauthtest.Config) { c.DeviceScript = []oauthtest.DeviceStep{oauthtest.DevicePending} })
	ctx, cancel := context.WithCancel(t.Context())
	c := e.newClient(t, auth.WithFlow(auth.FlowDevice), auth.WithDeviceAuthorizationHandler(func(context.Context, *auth.DeviceAuthorization) error {
		cancel()
		return nil
	}))
	_, err := c.Login(ctx)
	wantErr(t, err, context.Canceled)

	failing := e.newClient(t, auth.WithFlow(auth.FlowDevice), auth.WithDeviceAuthorizationHandler(func(context.Context, *auth.DeviceAuthorization) error {
		return errors.New("window closed")
	}))
	if _, err := failing.Login(t.Context()); err == nil || !strings.Contains(err.Error(), "window closed") {
		t.Fatalf("handler error: %v", err)
	}
}

func TestAutoFlowSelection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		browser   bool
		noDevice  bool
		noAuthz   bool
		grants    []string
		want      oauthtest.Endpoint
		wantError error
	}{
		{name: "browser available", browser: true, want: oauthtest.EndpointAuthorization},
		{name: "headless", want: oauthtest.EndpointDeviceAuthorization},
		{name: "headless without device endpoint", noDevice: true, want: oauthtest.EndpointAuthorization},
		{name: "browser, but code grant not listed", browser: true, grants: []string{string(auth.GrantDeviceCode)}, want: oauthtest.EndpointDeviceAuthorization},
		{name: "neither", noDevice: true, noAuthz: true, wantError: auth.ErrUnsupportedFlow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := plainEnv(t, nil)
			if tc.noDevice {
				e.as.SetMetadata("device_authorization_endpoint", nil)
			}
			if tc.noAuthz {
				e.as.SetMetadata("authorization_endpoint", nil)
			}
			if tc.grants != nil {
				e.as.SetMetadata("grant_types_supported", tc.grants)
			}
			c := e.newClient(t, auth.WithBrowser(tc.browser), auth.WithBrowserOpener(e.as.OpenBrowser), auth.WithLoginTimeout(100*time.Millisecond))
			_, err := c.Login(t.Context())
			if tc.wantError != nil {
				wantErr(t, err, tc.wantError)
				return
			}
			if tc.want == oauthtest.EndpointAuthorization && !tc.browser {
				// The browser flow without a browser: the URL is printed.
				if !strings.Contains(e.errOut.String(), "Open this URL in a browser") {
					t.Fatalf("browser flow not chosen: %v\n%s", err, e.errOut.String())
				}
				return
			}
			if len(e.as.Requests(tc.want)) == 0 {
				t.Fatalf("no request to %s (err %v)", tc.want, err)
			}
		})
	}
}
