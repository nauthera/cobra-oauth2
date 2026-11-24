package oauthtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Endpoint names a kind of endpoint the server implements. Requests are
// recorded per kind, and [Server.Override] replaces one.
type Endpoint string

// Endpoints of the server. The paths come from the metadata document, so a
// fixture decides where each one lives.
const (
	EndpointDiscovery           Endpoint = "discovery"
	EndpointAuthorization       Endpoint = "authorization"
	EndpointToken               Endpoint = "token"
	EndpointDeviceAuthorization Endpoint = "device_authorization"
	EndpointRevocation          Endpoint = "revocation"
	EndpointIntrospection       Endpoint = "introspection"
	EndpointUserInfo            Endpoint = "userinfo"
	EndpointJWKS                Endpoint = "jwks"
	EndpointPAR                 Endpoint = "pushed_authorization"
	EndpointEndSession          Endpoint = "end_session"
)

// metadataEndpoints maps metadata members to the endpoint they name.
var metadataEndpoints = map[string]Endpoint{
	"authorization_endpoint":                EndpointAuthorization,
	"token_endpoint":                        EndpointToken,
	"device_authorization_endpoint":         EndpointDeviceAuthorization,
	"revocation_endpoint":                   EndpointRevocation,
	"introspection_endpoint":                EndpointIntrospection,
	"userinfo_endpoint":                     EndpointUserInfo,
	"jwks_uri":                              EndpointJWKS,
	"pushed_authorization_request_endpoint": EndpointPAR,
	"end_session_endpoint":                  EndpointEndSession,
}

// DiscoveryMode selects where the metadata document is served.
type DiscoveryMode int

// Discovery modes.
const (
	// DiscoveryBoth serves the document at the OpenID Connect location
	// ({issuer}/.well-known/openid-configuration) and at the RFC 8414 § 3.1
	// location (well-known segment inserted before the issuer's path).
	DiscoveryBoth DiscoveryMode = iota
	// DiscoveryOIDC serves only the OpenID Connect location.
	DiscoveryOIDC
	// DiscoveryRFC8414 serves only the RFC 8414 location.
	DiscoveryRFC8414
	// DiscoveryNone serves no document (GitHub). The metadata still
	// decides where the endpoints are.
	DiscoveryNone
)

// DeviceStep is the outcome of one device-flow poll.
type DeviceStep int

// Device poll outcomes, in the order a script lists them.
const (
	// DeviceApprove issues the tokens.
	DeviceApprove DeviceStep = iota
	// DevicePending answers authorization_pending.
	DevicePending
	// DeviceSlowDown answers slow_down and lengthens the interval by 5 s.
	DeviceSlowDown
	// DeviceDeny answers access_denied.
	DeviceDeny
	// DeviceExpire answers expired_token.
	DeviceExpire
)

// RefreshPolicy is how the server answers a refresh token grant.
type RefreshPolicy int

// Refresh policies.
const (
	// RefreshRotate issues a new refresh token each time; presenting a
	// spent one revokes the whole grant (nauthera, Okta, Auth0, Entra).
	RefreshRotate RefreshPolicy = iota
	// RefreshReuse returns the same refresh token (Keycloak's default).
	RefreshReuse
	// RefreshOmit leaves refresh_token out of the response; the client
	// keeps its old one (Google, Cognito).
	RefreshOmit
)

// Client is a client registered at the server.
type Client struct {
	// ID is the client_id.
	ID string
	// Secret is the client secret. Empty means a public client
	// (token_endpoint_auth_method none).
	Secret string
	// RedirectURIs are the registered redirect URIs. A loopback http URI
	// matches a request that differs only by port (RFC 8252 § 7.3).
	RedirectURIs []string
	// Grants limits the grant types the client may use; empty allows all.
	Grants []string
}

// DPoPPolicy configures DPoP (RFC 9449) at the server.
type DPoPPolicy struct {
	// Enabled verifies DPoP proofs and issues DPoP-bound tokens when a
	// request carries one. Without it a DPoP header is ignored and Bearer
	// tokens are issued.
	Enabled bool
	// RequireNonce answers a proof without a current server nonce with
	// use_dpop_nonce (nauthera, Okta).
	RequireNonce bool
}

// Quirks reproduce provider deviations from the RFCs.
type Quirks struct {
	// ErrorStatus overrides the HTTP status of an error response by error
	// code; the key "*" applies to every code (GitHub: 200).
	ErrorStatus map[string]int
	// FormEncoded answers with application/x-www-form-urlencoded bodies,
	// as GitHub does when it ignores the Accept header.
	FormEncoded bool
	// StringNumbers encodes expires_in and interval as strings (Entra v1,
	// ADFS).
	StringNumbers bool
	// VerificationURL spells verification_uri the pre-RFC way (Google).
	VerificationURL bool
	// NoVerificationURIComplete leaves out verification_uri_complete.
	NoVerificationURIComplete bool
	// NoExpiresIn leaves expires_in out of token responses (GitHub OAuth
	// apps).
	NoExpiresIn bool
	// TokenType replaces the token_type spelling of Bearer tokens, for
	// example "bearer" (GitHub).
	TokenType string
	// ScopeSeparator joins the granted scope in responses ("," on GitHub).
	ScopeSeparator string
	// SlowDownInterval sends the new interval with slow_down (GitHub).
	SlowDownInterval bool
	// ExtraTokenFields are added to every successful token response.
	ExtraTokenFields map[string]any
	// WrongIss names another issuer in the authorization response.
	WrongIss bool
	// OmitIss leaves iss out of the authorization response.
	OmitIss bool
	// DeviceAuthWithoutSecret lets a confidential client call the device
	// authorization endpoint with its client_id alone (GitHub, Google).
	DeviceAuthWithoutSecret bool
	// ErrorURIBase, when set, adds an error_uri of ErrorURIBase + code to
	// every error response (nauthera points it at the code's runbook).
	ErrorURIBase string
}

// Config configures a [Server]. The zero value is a plain OpenID Connect
// server with one public client, "test-cli".
type Config struct {
	// TLS serves https with httptest's certificate; use [Server.Client] as
	// the HTTP client. Otherwise the server is loopback http.
	TLS bool
	// IssuerPath is appended to the server URL to form the issuer, for
	// example "/orgs/acme" or "/" (Auth0's trailing slash).
	IssuerPath string
	// Metadata is the discovery document, with the placeholders {{issuer}},
	// {{base}} (the issuer without a trailing slash) and {{origin}}. Nil
	// generates one listing every endpoint below {{base}}.
	Metadata map[string]any
	// Discovery selects where the document is served.
	Discovery DiscoveryMode
	// Unadvertised serves endpoints the metadata does not list, by URL
	// with placeholders (GitLab's device endpoint).
	Unadvertised map[Endpoint]string
	// Clients are the registered clients. Nil registers one public client
	// "test-cli" with the redirect URI http://127.0.0.1/callback.
	Clients []Client
	// Now is the server's clock. Nil is time.Now.
	Now func() time.Time
	// AccessTokenTTL is the access token lifetime. Zero is 10 minutes.
	AccessTokenTTL time.Duration
	// RefreshPolicy is how refresh token grants are answered.
	RefreshPolicy RefreshPolicy
	// RefreshScope, when set, issues a refresh token only when the granted
	// scope contains it (nauthera and Entra: offline_access).
	RefreshScope string
	// NoRefreshTokens never issues refresh tokens (GitHub OAuth apps).
	NoRefreshTokens bool
	// NoIDTokens never issues ID tokens (GitHub).
	NoIDTokens bool
	// DPoP configures DPoP.
	DPoP DPoPPolicy
	// DeviceScript lists the outcome of each device poll; the last one
	// repeats. Nil approves the first poll. [Server.ApproveDevice] and
	// [Server.DenyDevice] decide before the script does.
	DeviceScript []DeviceStep
	// DeviceInterval is the polling interval in seconds. Zero is 5.
	DeviceInterval int
	// DeviceExpiresIn is the device code lifetime in seconds. Zero is 900.
	DeviceExpiresIn int
	// EnforceInterval answers slow_down, and lengthens the interval, when
	// a client polls sooner than the interval allows.
	EnforceInterval bool
	// UserCode is the user code to hand out. Empty is "WDJB-MJHT".
	UserCode string
	// VerificationURI is the device verification page, with placeholders.
	// Empty is {{base}}/device.
	VerificationURI string
	// SigningAlg is the ID token signature algorithm: "ES256" (the
	// default, as nauthera) or "RS256" (Google, Entra, Auth0).
	SigningAlg string
	// Subject is the sub of ID tokens and userinfo. Empty is "user-1".
	Subject string
	// IDTokenIssuer replaces the iss of ID tokens, with placeholders
	// (Google's legacy "accounts.google.com").
	IDTokenIssuer string
	// IDTokenClaims are added to every ID token (tid, email, name).
	IDTokenClaims map[string]any
	// TokenExchange implements RFC 8693. Without it the token endpoint
	// answers the grant with 503 temporarily_unavailable, as nauthera does.
	TokenExchange bool
	// RevokeUnavailable is how many revocation requests are answered with
	// 503 temporarily_unavailable before revocation works.
	RevokeUnavailable int
	// Consent decides authorization requests; nil approves them all.
	Consent func(params url.Values) bool
	// Quirks reproduce provider deviations.
	Quirks Quirks
}

// Request is a request the server received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Form   url.Values
	Header http.Header
}

// Server is a fake authorization server. It embeds the httptest server, so
// URL, Client and Close are available.
type Server struct {
	*httptest.Server

	t      testing.TB
	cfg    Config
	issuer string
	base   string
	key    crypto.Signer
	alg    string

	mu             sync.Mutex
	metadata       map[string]any
	routes         map[string]Endpoint
	overrides      map[Endpoint]http.HandlerFunc
	requests       []recordedRequest
	codes          map[string]*authCode
	pushed         map[string]*pushedRequest
	devices        map[string]*deviceSession
	access         map[string]*accessToken
	refresh        map[string]*refreshToken
	families       map[int]bool // grant family -> revoked
	jtis           map[string]bool
	nonces         []string
	revokeFails    int
	seq            int
	callbackStatus int
}

type recordedRequest struct {
	kind Endpoint
	req  Request
}

// DefaultClientID is the client registered when Config.Clients is nil.
const DefaultClientID = "test-cli"

// New starts a server and stops it when the test ends.
func New(t testing.TB, cfg Config) *Server {
	t.Helper()
	alg := cfg.SigningAlg
	var (
		key crypto.Signer
		err error
	)
	switch alg {
	case "", "ES256":
		alg = "ES256"
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RS256":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("oauthtest: unsupported signing algorithm %q", alg)
	}
	if err != nil {
		t.Fatalf("oauthtest: generate signing key: %v", err)
	}
	if cfg.Clients == nil {
		cfg.Clients = []Client{{ID: DefaultClientID, RedirectURIs: []string{"http://127.0.0.1/callback"}}}
	}
	s := &Server{
		t:         t,
		cfg:       cfg,
		key:       key,
		alg:       alg,
		overrides: map[Endpoint]http.HandlerFunc{},
		codes:     map[string]*authCode{},
		pushed:    map[string]*pushedRequest{},
		devices:   map[string]*deviceSession{},
		access:    map[string]*accessToken{},
		refresh:   map[string]*refreshToken{},
		families:  map[int]bool{},
		jtis:      map[string]bool{},

		revokeFails: cfg.RevokeUnavailable,
	}
	if cfg.TLS {
		s.Server = httptest.NewTLSServer(s)
	} else {
		s.Server = httptest.NewServer(s)
	}
	t.Cleanup(s.Close)

	s.issuer = s.URL + cfg.IssuerPath
	s.base = strings.TrimSuffix(s.issuer, "/")
	md := cfg.Metadata
	if md == nil {
		md = s.defaultMetadata()
	}
	s.metadata, _ = s.expand(md).(map[string]any)
	s.rebuildRoutes()
	return s
}

func (s *Server) defaultMetadata() map[string]any {
	return map[string]any{ //nolint:gosec // G101: metadata member names, not credentials
		"issuer":                                "{{issuer}}",
		"authorization_endpoint":                "{{base}}/authorize",
		"token_endpoint":                        "{{base}}/token",
		"device_authorization_endpoint":         "{{base}}/device_authorization",
		"revocation_endpoint":                   "{{base}}/revoke",
		"introspection_endpoint":                "{{base}}/introspect",
		"userinfo_endpoint":                     "{{base}}/userinfo",
		"jwks_uri":                              "{{base}}/jwks",
		"end_session_endpoint":                  "{{base}}/end_session",
		"pushed_authorization_request_endpoint": "{{base}}/par",
		"response_types_supported":              []any{"code"},
		"code_challenge_methods_supported":      []any{"S256"},
		"id_token_signing_alg_values_supported": []any{"ES256"},
		"token_endpoint_auth_methods_supported": []any{"client_secret_basic", "client_secret_post", "none"},
	}
}

// expand replaces the placeholders in every string of v.
func (s *Server) expand(v any) any {
	switch x := v.(type) {
	case string:
		return strings.NewReplacer("{{issuer}}", s.issuer, "{{base}}", s.base, "{{origin}}", s.URL).Replace(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = s.expand(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.expand(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.expand(e)
		}
		return out
	default:
		return v
	}
}

// rebuildRoutes maps the paths of the metadata's endpoints to their kind.
// The caller holds mu or owns s exclusively.
func (s *Server) rebuildRoutes() {
	s.routes = map[string]Endpoint{}
	add := func(raw string, kind Endpoint) {
		u, err := url.Parse(raw)
		if raw == "" || err != nil || u.Host != s.Listener.Addr().String() {
			return
		}
		s.routes[u.Path] = kind
	}
	for member, kind := range metadataEndpoints {
		raw, _ := s.metadata[member].(string)
		add(raw, kind)
	}
	for kind, raw := range s.cfg.Unadvertised {
		u, _ := s.expand(raw).(string)
		add(u, kind)
	}
}

func (s *Server) routeOf(path string) Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[path]
}

// Issuer returns the issuer identifier.
func (s *Server) Issuer() string { return s.issuer }

// Metadata returns a copy of the metadata document.
func (s *Server) Metadata() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.metadata)
	var cp map[string]any
	_ = json.Unmarshal(b, &cp)
	return cp
}

// SetMetadata sets (or, with a nil value, deletes) a metadata member. The
// value may use the placeholders.
func (s *Server) SetMetadata(member string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == nil {
		delete(s.metadata, member)
	} else {
		s.metadata[member] = s.expand(value)
	}
	s.rebuildRoutes()
}

// Override replaces the handler of an endpoint. Requests are still
// recorded.
func (s *Server) Override(kind Endpoint, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overrides[kind] = h
}

// Requests returns the requests received at an endpoint, in order.
func (s *Server) Requests(kind Endpoint) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.requests {
		if r.kind == kind {
			out = append(out, r.req)
		}
	}
	return out
}

// CallbackStatus returns the HTTP status of the client's loopback page
// after the last [Server.OpenBrowser], or 0.
func (s *Server) CallbackStatus() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callbackStatus
}

func (s *Server) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// discoveryKind reports whether path is a metadata location this server
// serves.
func (s *Server) isDiscoveryPath(p string) bool {
	u, _ := url.Parse(s.issuer)
	issuerPath := strings.TrimSuffix(u.EscapedPath(), "/")
	oidc := issuerPath + "/.well-known/openid-configuration"
	rfc := "/.well-known/oauth-authorization-server" + issuerPath
	switch s.cfg.Discovery {
	case DiscoveryBoth:
		return p == oidc || p == rfc
	case DiscoveryOIDC:
		return p == oidc
	case DiscoveryRFC8414:
		return p == rfc
	default:
		return false
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The Date header follows the server clock, which a test shares with
	// the client: DPoP clients correct their iat from it.
	w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}

	s.mu.Lock()
	kind, routed := s.routes[r.URL.Path]
	switch {
	case s.isDiscoveryPath(r.URL.Path):
		kind, routed = EndpointDiscovery, true
	case !routed && strings.Contains(r.URL.Path, "/.well-known/"):
		// A metadata location this server does not serve: recorded, so a
		// test can count the client's attempts, and answered 404.
		kind = EndpointDiscovery
	}
	if kind != "" {
		s.requests = append(s.requests, recordedRequest{kind: kind, req: Request{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Form: cloneValues(r.PostForm), Header: r.Header.Clone(),
		}})
	}
	override := s.overrides[kind]
	s.mu.Unlock()

	if !routed {
		http.NotFound(w, r)
		return
	}
	if override != nil && routed {
		override(w, r)
		return
	}
	switch kind {
	case EndpointDiscovery:
		s.serveDiscovery(w, r)
	case EndpointJWKS:
		s.serveJWKS(w, r)
	case EndpointAuthorization:
		s.serveAuthorize(w, r)
	case EndpointPAR:
		s.servePAR(w, r)
	case EndpointToken:
		s.serveToken(w, r)
	case EndpointDeviceAuthorization:
		s.serveDeviceAuthorization(w, r)
	case EndpointRevocation:
		s.serveRevoke(w, r)
	case EndpointIntrospection:
		s.serveIntrospect(w, r)
	case EndpointUserInfo:
		s.serveUserInfo(w, r)
	case EndpointEndSession:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Signed out</title>"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.Metadata())
}

// writeJSON writes v as a JSON response that must not be cached.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeBody writes a token-endpoint style body, JSON or form-encoded as the
// quirks say.
func (s *Server) writeBody(w http.ResponseWriter, status int, body map[string]any) {
	if !s.cfg.Quirks.FormEncoded {
		writeJSON(w, status, body)
		return
	}
	form := url.Values{}
	for k, v := range body {
		switch x := v.(type) {
		case string:
			form.Set(k, x)
		default:
			b, _ := json.Marshal(x)
			form.Set(k, string(b))
		}
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(form.Encode()))
}

// oauthError writes an RFC 6749 § 5.2 error response.
func (s *Server) oauthError(w http.ResponseWriter, status int, code, desc string) {
	if st, ok := s.cfg.Quirks.ErrorStatus[code]; ok {
		status = st
	} else if st, ok := s.cfg.Quirks.ErrorStatus["*"]; ok {
		status = st
	}
	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	if s.cfg.Quirks.ErrorURIBase != "" {
		body["error_uri"] = s.cfg.Quirks.ErrorURIBase + code
	}
	if status == http.StatusUnauthorized && code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	s.writeBody(w, status, body)
}

func (s *Server) number(n int) any {
	if s.cfg.Quirks.StringNumbers {
		b, _ := json.Marshal(n)
		return string(b)
	}
	return n
}

func (s *Server) clientByID(id string) *Client {
	for i := range s.cfg.Clients {
		if s.cfg.Clients[i].ID == id {
			return &s.cfg.Clients[i]
		}
	}
	return nil
}

// randomString returns n random bytes, base64url-encoded.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}

// LoadJSON reads a JSON object from a file, typically a fixture under
// testdata, for Config.Metadata.
func LoadJSON(t testing.TB, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("oauthtest: read fixture: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("oauthtest: fixture %s: %v", path, err)
	}
	return m
}

// RecordedResponse is a response captured from a real server, as stored in
// a fixture: status, headers and a JSON (or string) body.
type RecordedResponse struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header"`
	Body   json.RawMessage   `json:"body"`
}

// Replay returns a handler that answers every request with the response
// recorded in the fixture at path, for [Server.Override]. Placeholders in
// the body are expanded.
func (s *Server) Replay(path string) http.HandlerFunc {
	s.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		s.t.Fatalf("oauthtest: read fixture: %v", err)
	}
	var rec RecordedResponse
	if err := json.Unmarshal(b, &rec); err != nil {
		s.t.Fatalf("oauthtest: fixture %s: %v", path, err)
	}
	raw := string(rec.Body)
	var str string
	if json.Unmarshal(rec.Body, &str) == nil {
		raw = str
	}
	body, _ := s.expand(raw).(string)
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range rec.Header {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" && body != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(rec.Status)
		_, _ = w.Write([]byte(body))
	}
}
