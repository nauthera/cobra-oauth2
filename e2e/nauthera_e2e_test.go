//go:build e2e

// Package e2e runs the library against a live nauthera-server. The tests
// are behind the e2e build tag (`just e2e`, or `go test -tags e2e ./e2e/...`)
// and skip unless the server and client are configured through the
// environment:
//
//	NAUTHERA_E2E_ISSUER             issuer URL of the server (required)
//	NAUTHERA_E2E_CLIENT_ID          a public client with the device grant (required)
//	NAUTHERA_E2E_SCOPES             scopes to request, comma- or space-separated
//	                                (default "openid offline_access")
//	NAUTHERA_E2E_CLIENT_SECRET      secret of a confidential client registered for
//	                                client_credentials; enables those tests
//	NAUTHERA_E2E_SERVICE_CLIENT_ID  that confidential client's ID (default:
//	                                NAUTHERA_E2E_CLIENT_ID)
//	NAUTHERA_E2E_CA_FILE            PEM bundle to trust in addition to the system
//	                                roots, for a server with a local certificate
//	NAUTHERA_E2E_USER_EMAIL         a test user's email and password: the
//	NAUTHERA_E2E_USER_PASSWORD      automated tests sign in as that user and
//	                                approve or deny device codes for it
//	NAUTHERA_E2E_INTERACTIVE=1      run the full device login, which waits for a
//	                                person to approve the code in a browser
//	NAUTHERA_E2E_DPOP=1             use DPoP in the interactive login
//
// The protocol tests use discovery and the RFCs only, so they also run
// against another standards-compliant server. The automated user steps are
// the one exception: they call nauthera's hosted sign-in API (see
// hostedUser), which is a server detail and may change.
// e2e/README.md describes how to get a server, a client and a test user.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

type settings struct {
	issuer, clientID, serviceID, secret string
	userEmail, userPassword             string
	scopes                              []string
	httpClient                          *http.Client
	interactive, dpop                   bool
}

func load(t *testing.T) settings {
	t.Helper()
	s := settings{
		issuer:       os.Getenv("NAUTHERA_E2E_ISSUER"),
		clientID:     os.Getenv("NAUTHERA_E2E_CLIENT_ID"),
		secret:       os.Getenv("NAUTHERA_E2E_CLIENT_SECRET"),
		serviceID:    os.Getenv("NAUTHERA_E2E_SERVICE_CLIENT_ID"),
		userEmail:    os.Getenv("NAUTHERA_E2E_USER_EMAIL"),
		userPassword: os.Getenv("NAUTHERA_E2E_USER_PASSWORD"),
		interactive:  os.Getenv("NAUTHERA_E2E_INTERACTIVE") == "1",
		dpop:         os.Getenv("NAUTHERA_E2E_DPOP") == "1",
	}
	if s.issuer == "" || s.clientID == "" {
		t.Skip("set NAUTHERA_E2E_ISSUER and NAUTHERA_E2E_CLIENT_ID to run the live tests (e2e/README.md)")
	}
	if s.serviceID == "" {
		s.serviceID = s.clientID
	}
	s.scopes = strings.FieldsFunc(os.Getenv("NAUTHERA_E2E_SCOPES"), func(r rune) bool { return r == ',' || r == ' ' })
	if len(s.scopes) == 0 {
		s.scopes = []string{"openid", "offline_access"}
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile := os.Getenv("NAUTHERA_E2E_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatalf("NAUTHERA_E2E_CA_FILE: %v", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("NAUTHERA_E2E_CA_FILE %s holds no PEM certificate", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	s.httpClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return s
}

func (s settings) client(t *testing.T, opts ...auth.Option) *auth.Client {
	t.Helper()
	base := []auth.Option{
		auth.Nauthera(s.issuer),
		auth.WithClientID(s.clientID),
		auth.WithScopes(s.scopes...),
		auth.WithHTTPClient(s.httpClient),
		auth.WithStorage(storage.NewMemory()),
		auth.WithBrowser(false),
		auth.WithAppName("cobra-oauth2-e2e"),
	}
	c, err := auth.NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestDiscovery(t *testing.T) {
	s := load(t)
	md, err := s.client(t).Metadata(t.Context())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if md.Issuer != s.issuer {
		t.Fatalf("issuer %q, want exactly %q", md.Issuer, s.issuer)
	}
	if !strings.HasPrefix(md.TokenEndpoint, "https://") {
		t.Fatalf("token endpoint %q is not https", md.TokenEndpoint)
	}
	if !slices.Contains(md.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("S256 is not advertised: %v", md.CodeChallengeMethodsSupported)
	}
	if md.DeviceAuthorizationEndpoint == "" || !md.SupportsGrant(auth.GrantDeviceCode) {
		t.Errorf("the device grant is not advertised")
	}
	if !md.AuthorizationResponseIssParameterSupported {
		t.Errorf("authorization_response_iss_parameter_supported is not set (RFC 9207)")
	}
	t.Logf("server advertises DPoP algorithms %v, PAR endpoint %q (required: %v)",
		md.DPoPSigningAlgValuesSupported, md.PushedAuthorizationRequestEndpoint, md.RequirePushedAuthorizationRequests)

	// The issuer comparison is exact: the same server named with a trailing
	// slash is a different issuer, and its document must be refused.
	c := s.client(t, auth.WithIssuer(strings.TrimSuffix(s.issuer, "/")+"/"))
	if _, err := c.Metadata(t.Context()); !errors.Is(err, auth.ErrDiscovery) {
		t.Fatalf("a document for another issuer string was accepted: %v", err)
	}
}

// pendingWatcher is middleware that cancels the poll once the server
// answered authorization_pending, so the device flow can be exercised up to
// that point without a person.
type pendingWatcher struct {
	mu     sync.Mutex
	codes  []string
	cancel context.CancelFunc
}

func (p *pendingWatcher) middleware(next auth.EndpointHandler) auth.EndpointHandler {
	return func(ctx context.Context, req *auth.EndpointRequest) (*auth.EndpointResponse, error) {
		resp, err := next(ctx, req)
		if err != nil || req.Kind != auth.EndpointToken {
			return resp, err
		}
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp.Body, &body)
		p.mu.Lock()
		p.codes = append(p.codes, body.Error)
		p.mu.Unlock()
		if body.Error == "authorization_pending" {
			p.cancel()
		}
		return resp, err
	}
}

func (p *pendingWatcher) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.codes)
}

func testDeviceStart(t *testing.T, opts ...auth.Option) {
	t.Helper()
	s := load(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	watch := &pendingWatcher{cancel: cancel}
	c := s.client(t, append(opts, auth.WithEndpointMiddleware(watch.middleware))...)

	da, err := c.StartDeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	if da.UserCode == "" || !strings.HasPrefix(da.VerificationURI, "https://") || !da.ExpiresAt.After(time.Now()) {
		t.Fatalf("device authorization response: %s", da)
	}
	t.Logf("user code %s at %s (not approving)", da.UserCode, da.VerificationURI)

	_, err = c.PollDeviceAuthorization(ctx, da)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("poll ended with %v; want it canceled after authorization_pending (saw %v)", err, watch.seen())
	}
	if codes := watch.seen(); !slices.Contains(codes, "authorization_pending") {
		t.Fatalf("token endpoint answers %v, want authorization_pending", codes)
	}
}

func TestDeviceAuthorizationPending(t *testing.T) { testDeviceStart(t) }

func TestDeviceAuthorizationPendingWithDPoP(t *testing.T) {
	s := load(t)
	md, err := s.client(t).Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(md.DPoPSigningAlgValuesSupported) == 0 {
		t.Skip("the server does not advertise DPoP")
	}
	// The device session is bound with dpop_jkt, and every poll carries a
	// proof (after the server's nonce round trip).
	testDeviceStart(t, auth.WithDPoP())
}

func TestTokenExchangeIsGated(t *testing.T) {
	s := load(t)
	c := s.client(t)
	md, err := c.Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.SupportsGrant(auth.GrantTokenExchange) {
		t.Skip("the server advertises token exchange")
	}
	_, err = c.ExchangeToken(t.Context(), auth.ExchangeRequest{SubjectToken: "x", SubjectTokenType: auth.AccessTokenType})
	if !errors.Is(err, auth.ErrUnsupportedFlow) {
		t.Fatalf("ExchangeToken: %v", err)
	}
}

func TestClientCredentials(t *testing.T) {
	s := load(t)
	if s.secret == "" {
		t.Skip("set NAUTHERA_E2E_CLIENT_SECRET (and NAUTHERA_E2E_SERVICE_CLIENT_ID) for the client credentials tests")
	}
	c := s.client(t, auth.WithClientID(s.serviceID), auth.WithClientSecret(s.secret),
		auth.WithFlow(auth.FlowClientCredentials), auth.WithScopes())
	tok, err := c.Login(t.Context())
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken != "" {
		t.Fatalf("token set: %v", tok)
	}
	in, err := c.Introspect(t.Context(), tok.AccessToken)
	if err != nil || !in.Active {
		t.Fatalf("introspection of a fresh token: %+v %v", in, err)
	}
	if err := c.Logout(t.Context()); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if in, err := c.Introspect(t.Context(), tok.AccessToken); err == nil && in.Active {
		t.Logf("the access token is still active after revocation (JWT access tokens cannot be revoked by value)")
	}

	bad := s.client(t, auth.WithClientID(s.serviceID), auth.WithClientSecret(s.secret+"-wrong"),
		auth.WithFlow(auth.FlowClientCredentials))
	if _, err := bad.Login(t.Context()); !errors.Is(err, auth.ErrInvalidClient) {
		t.Fatalf("a wrong secret: %v", err)
	}
}

// TestInteractiveDeviceLogin is the whole lifecycle with a person in the
// loop: device login, a call to userinfo, refresh with rotation, reuse
// detection, logout.
func TestInteractiveDeviceLogin(t *testing.T) {
	s := load(t)
	if !s.interactive {
		t.Skip("set NAUTHERA_E2E_INTERACTIVE=1 to approve a device login by hand")
	}
	opts := []auth.Option{auth.WithFlow(auth.FlowDevice), auth.WithOutput(io.Discard, os.Stderr)}
	if s.dpop {
		opts = append(opts, auth.WithDPoP())
	}
	c := s.client(t, opts...)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	tok, err := c.Login(ctx)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tok.RefreshToken == "" && slices.Contains(s.scopes, "offline_access") {
		t.Fatal("no refresh token although offline_access was requested (is refresh allowed for the client?)")
	}
	if s.dpop && tok.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("token type %s, want DPoP", tok.TokenType)
	}

	md, err := c.Metadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if md.UserinfoEndpoint != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, md.UserinfoEndpoint, http.NoBody)
		resp, err := (&http.Client{Transport: c.Transport(s.httpClient.Transport)}).Do(req)
		if err != nil {
			t.Fatalf("userinfo: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo answered %d", resp.StatusCode)
		}
	}

	if tok.RefreshToken != "" {
		next, err := c.Refresh(ctx, tok)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if next.RefreshToken == tok.RefreshToken {
			t.Logf("the server did not rotate the refresh token")
		} else if _, err := c.Refresh(ctx, tok); !errors.Is(err, auth.ErrLoginRequired) {
			// Reusing the spent token must be refused, and revokes the grant.
			t.Fatalf("reuse of a rotated refresh token: %v", err)
		}
	}
	if err := c.Logout(ctx); err != nil && !errors.Is(err, auth.ErrRevocationFailed) {
		t.Fatalf("logout: %v", err)
	}
}

// hostedUser acts for a person through nauthera's hosted sign-in API, the
// JSON endpoints its sign-in and device pages call: it signs in with a
// password, keeps the session cookie, and approves or denies a device code
// (RFC 8628 § 3.3 leaves that step to the server). This is the only server
// detail the tests depend on. When a server change breaks it and not the
// protocol, fix it here, not in the library.
type hostedUser struct {
	issuer, clientID, email, password string
	hc                                *http.Client
	signedIn                          bool
}

// user returns the test user, or skips the test when none is configured.
func (s settings) user(t *testing.T) *hostedUser {
	t.Helper()
	if s.userEmail == "" || s.userPassword == "" {
		t.Skip("set NAUTHERA_E2E_USER_EMAIL and NAUTHERA_E2E_USER_PASSWORD to approve device codes automatically")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := *s.httpClient
	hc.Jar = jar
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hostedUser{
		issuer: strings.TrimSuffix(s.issuer, "/"), clientID: s.clientID,
		email: s.userEmail, password: s.userPassword, hc: &hc,
	}
}

// post sends a JSON body to a hosted-UI endpoint below the issuer and
// decodes the JSON answer into out.
func (u *hostedUser) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.issuer+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// The server's CSRF guard wants JSON; without Origin and
	// Sec-Fetch-Site (no browser) it accepts the request.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := u.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var problem struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(data, &problem)
		return fmt.Errorf("POST %s: %s %s %s %s", path, resp.Status, problem.Code, problem.Title, problem.Detail)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("POST %s: %w", path, err)
		}
	}
	return nil
}

func (u *hostedUser) signIn(ctx context.Context) error {
	if u.signedIn {
		return nil
	}
	var step struct {
		MFARequired               bool `json:"mfaRequired"`
		SetupRequired             bool `json:"setupRequired"`
		EmailVerificationRequired bool `json:"emailVerificationRequired"`
		PasskeyOffered            bool `json:"passkeyOffered"`
	}
	// A sign-in must continue something; the client the codes are for will do.
	err := u.post(ctx, "/v1/auth/sign-in", map[string]any{
		"email": u.email, "password": u.password, "client_id": u.clientID,
	}, &step)
	if err != nil {
		return fmt.Errorf("sign in as the test user: %w", err)
	}
	if step.MFARequired || step.SetupRequired || step.EmailVerificationRequired || step.PasskeyOffered {
		return fmt.Errorf("sign in as the test user: the server wants another step (%+v); "+
			"use a test user with a verified address and no second factor", step)
	}
	u.signedIn = true
	return nil
}

// decide approves or denies the device authorization with userCode.
func (u *hostedUser) decide(ctx context.Context, userCode string, approve bool) error {
	if err := u.signIn(ctx); err != nil {
		return err
	}
	var res struct {
		Approved bool `json:"approved"`
	}
	if err := u.post(ctx, "/v1/auth/device/decision", map[string]any{"user_code": userCode, "approve": approve}, &res); err != nil {
		return fmt.Errorf("device decision: %w", err)
	}
	if res.Approved != approve {
		return fmt.Errorf("device decision: approved=%v, want %v", res.Approved, approve)
	}
	return nil
}

// handler returns a DeviceAuthorizationHandler that decides for the user
// as soon as the code is issued, so polling finds the decision.
func (u *hostedUser) handler(approve bool) auth.DeviceAuthorizationHandler {
	return func(ctx context.Context, da *auth.DeviceAuthorization) error {
		return u.decide(ctx, da.UserCode, approve)
	}
}

// TestAutomatedDeviceLogin is the device lifecycle without a person:
// approval, DPoP binding when the server offers it, a call through
// Client.Transport, refresh rotation, reuse detection, and revocation.
func TestAutomatedDeviceLogin(t *testing.T) {
	s := load(t)
	u := s.user(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	md, err := s.client(t).Metadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	opts := []auth.Option{auth.WithFlow(auth.FlowDevice), auth.WithDeviceAuthorizationHandler(u.handler(true))}
	dpop := len(md.DPoPSigningAlgValuesSupported) > 0
	if dpop {
		opts = append(opts, auth.WithDPoP())
	}
	c := s.client(t, opts...)

	tok, err := c.Login(ctx)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if dpop && tok.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("token type %s, want DPoP", tok.TokenType)
	}
	if tok.RefreshToken == "" && slices.Contains(s.scopes, "offline_access") {
		t.Fatal("no refresh token although offline_access was requested (is refresh allowed for the client?)")
	}
	if st, err := c.Status(ctx); err != nil || (slices.Contains(s.scopes, "openid") && st.Subject == "") {
		t.Fatalf("status after login: %+v %v", st, err)
	}

	if md.UserinfoEndpoint != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, md.UserinfoEndpoint, http.NoBody)
		resp, err := (&http.Client{Transport: c.Transport(s.httpClient.Transport)}).Do(req)
		if err != nil {
			t.Fatalf("userinfo: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo answered %d", resp.StatusCode)
		}
	}

	if tok.RefreshToken == "" {
		t.Skip("no refresh token; rotation, reuse detection and revocation need one")
	}
	next, err := c.Refresh(ctx, tok)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if dpop && next.TokenType != auth.TokenTypeDPoP {
		t.Fatalf("refreshed token type %s, want DPoP", next.TokenType)
	}
	if next.RefreshToken == tok.RefreshToken {
		t.Logf("the server did not rotate the refresh token")
	} else if _, err := c.Refresh(ctx, tok); !errors.Is(err, auth.ErrLoginRequired) {
		// Reusing the spent token must be refused, and revokes the grant.
		t.Fatalf("reuse of a rotated refresh token: %v", err)
	} else if _, err := c.Refresh(ctx, next); !errors.Is(err, auth.ErrLoginRequired) {
		t.Fatalf("the newest refresh token still works after reuse was detected: %v", err)
	}

	// A fresh login, revoked by logout: its refresh token must stop working.
	second := s.client(t, opts...)
	tok, err = second.Login(ctx)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if err := second.Logout(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := second.Refresh(ctx, tok); !errors.Is(err, auth.ErrLoginRequired) {
		t.Fatalf("refresh after logout: %v", err)
	}
}

// TestAutomatedDeviceDenial: a denied device code ends polling with
// access_denied.
func TestAutomatedDeviceDenial(t *testing.T) {
	s := load(t)
	u := s.user(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	c := s.client(t, auth.WithFlow(auth.FlowDevice), auth.WithDeviceAuthorizationHandler(u.handler(false)))
	if _, err := c.Login(ctx); !errors.Is(err, auth.ErrAccessDenied) {
		t.Fatalf("login after denial: %v, want access_denied", err)
	}
	if _, err := c.StoredToken(ctx); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Fatalf("a denied login stored something: %v", err)
	}
}
