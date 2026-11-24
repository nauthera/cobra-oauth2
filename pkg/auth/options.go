package auth

import (
	"context"
	"crypto"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// Option configures a [Client] and the commands built from one.
type Option func(*config)

// Flow selects how [Client.Login] obtains tokens.
type Flow string

// Login flows.
const (
	// FlowAuto picks the browser flow when a browser can be opened on this
	// machine and the provider has an authorization endpoint, otherwise the
	// device flow. It never picks the client credentials grant.
	FlowAuto Flow = "auto"
	// FlowDevice is the device authorization grant (RFC 8628).
	FlowDevice Flow = "device"
	// FlowBrowser is the authorization code grant with PKCE and a loopback
	// redirect (RFC 6749 § 4.1, RFC 7636, RFC 8252).
	FlowBrowser Flow = "browser"
	// FlowClientCredentials is the client credentials grant
	// (RFC 6749 § 4.4), for confidential clients such as CI jobs.
	FlowClientCredentials Flow = "client-credentials"
)

// GrantType is an OAuth 2.0 grant_type value.
type GrantType string

// Grant types this package sends or recognizes in grant_types_supported.
const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantClientCredentials GrantType = "client_credentials"
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantTokenExchange     GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: a grant type URN, not a credential
)

// String implements fmt.Stringer.
func (g GrantType) String() string { return string(g) }

// Endpoints lists authorization server endpoints. Any field left empty is
// taken from discovery, when discovery is enabled.
type Endpoints struct {
	Authorization       string
	Token               string
	DeviceAuthorization string
	Revocation          string
	Introspection       string
	UserInfo            string
	JWKS                string
	EndSession          string
	PushedAuthorization string
}

// Clock is the time source used for expiry checks and polling waits.
// Tests inject a fake one; the default is the system clock.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// BrowserOpener opens url in the user's browser.
type BrowserOpener func(ctx context.Context, url string) error

// DeviceAuthorizationHandler is called once the device authorization
// response arrived, instead of the default terminal prompt. It must not
// block until the user finished; polling starts when it returns.
type DeviceAuthorizationHandler func(ctx context.Context, da *DeviceAuthorization) error

type browserMode int

const (
	browserAuto browserMode = iota
	browserOn
	browserOff
)

type config struct {
	issuer       string
	discoveryURL string
	noDiscovery  bool
	overrides    Endpoints
	fallbacks    Endpoints // preset defaults, used only where discovery is silent

	clientID      string
	clientSecret  string
	authMethod    ClientAuthMethod
	authenticator ClientAuthenticator
	// exactRedirectPort makes the browser flow require WithRedirectPort:
	// the provider matches callback URLs exactly, port included, so an
	// ephemeral port would fail every login (Cognito).
	exactRedirectPort bool
	// deviceClientIDOnly sends only client_id to the device authorization
	// endpoint, for providers that authenticate the client at the token
	// endpoint only (GitHub, Google).
	deviceClientIDOnly bool
	// secretInBody makes ClientAuthAuto pick client_secret_post when a
	// secret is set, for providers that expect it there.
	secretInBody bool

	scopes          []string
	scopesSet       bool
	presetScopes    []string
	presetScopesSet bool
	audience        string
	resources       []string
	authParams      url.Values
	tokenParams     url.Values
	flow            Flow
	redirectHost    string
	redirectPort    int
	redirectPath    string
	loginTimeout    time.Duration
	browser         browserMode
	openBrowser     BrowserOpener
	qrCode          bool
	deviceHandler   DeviceAuthorizationHandler
	revokeOnLogout  bool
	verifyIDToken   bool
	idTokenLeeway   time.Duration
	issuerAliases   []string // extra accepted ID token issuers (Google)
	tenantIssuer    bool     // Entra {tenantid} placeholder in issuer
	expirySkew      time.Duration
	insecureHTTP    bool
	httpClient      *http.Client
	storage         storage.Provider
	locker          storage.Locker
	appName         string
	out, errOut     io.Writer
	logger          *slog.Logger
	clock           Clock
	middleware      []EndpointMiddleware
	userAgent       string
	providerName    string
	optErr          error // first error an option recorded

	dpop dpopMode
	par  PARMode

	// private_key_jwt (RFC 7523): the signing key and its kid.
	assertionKey   crypto.Signer
	assertionKeyID string
	assertionAud   AssertionAudience

	endSession *EndSessionOptions
}

const (
	defaultRedirectHost = "127.0.0.1"
	defaultRedirectPath = "/callback"
	defaultLoginTimeout = 5 * time.Minute
	defaultExpirySkew   = 30 * time.Second
	defaultLeeway       = 60 * time.Second
)

// defaultScopes are requested by the user flows when neither the caller nor
// a provider preset chose any: an ID token and a refresh token, nothing else.
var defaultScopes = []string{"openid", "offline_access"}

func defaultConfig() config {
	return config{
		redirectHost:   defaultRedirectHost,
		redirectPath:   defaultRedirectPath,
		loginTimeout:   defaultLoginTimeout,
		expirySkew:     defaultExpirySkew,
		idTokenLeeway:  defaultLeeway,
		verifyIDToken:  true,
		revokeOnLogout: true,
		out:            io.Discard,
		errOut:         io.Discard,
		clock:          systemClock{},
		userAgent:      defaultUserAgent,
		flow:           FlowAuto,
	}
}

// WithIssuer sets the authorization server's issuer identifier, for example
// "https://auth.example.com" or "https://auth.example.com/orgs/acme". The
// metadata is discovered from it (OpenID Connect Discovery, then RFC 8414)
// the first time a command needs it, never at construction, and the
// document's issuer must equal this value exactly.
func WithIssuer(issuer string) Option {
	return func(c *config) { c.issuer = issuer }
}

// WithDiscoveryURL sets the exact metadata document URL, for servers that
// publish it somewhere other than the standard well-known locations. Like
// [WithIssuer] it does no I/O. Without WithIssuer, the expected issuer is
// derived from the URL by removing the well-known suffix.
func WithDiscoveryURL(discoveryURL string) Option {
	return func(c *config) { c.discoveryURL = discoveryURL }
}

// WithoutDiscovery disables metadata discovery. Every endpoint the flows
// need must then be set with [WithEndpoints] or the WithXxxEndpoint options.
// [WithIssuer] still names the server for token storage.
func WithoutDiscovery() Option {
	return func(c *config) { c.noDiscovery = true }
}

// WithEndpoints sets endpoints explicitly. Non-empty fields take precedence
// over discovered values.
func WithEndpoints(e Endpoints) Option {
	return func(c *config) { mergeEndpoints(&c.overrides, e) }
}

// WithAuthorizationEndpoint sets the authorization endpoint explicitly.
func WithAuthorizationEndpoint(u string) Option {
	return func(c *config) { c.overrides.Authorization = u }
}

// WithTokenEndpoint sets the token endpoint explicitly.
func WithTokenEndpoint(u string) Option {
	return func(c *config) { c.overrides.Token = u }
}

// WithDeviceAuthorizationEndpoint sets the device authorization endpoint
// explicitly, for providers that support RFC 8628 without advertising it.
func WithDeviceAuthorizationEndpoint(u string) Option {
	return func(c *config) { c.overrides.DeviceAuthorization = u }
}

// WithRevocationEndpoint sets the RFC 7009 revocation endpoint explicitly.
func WithRevocationEndpoint(u string) Option {
	return func(c *config) { c.overrides.Revocation = u }
}

// WithPushedAuthorizationEndpoint sets the RFC 9126 pushed authorization
// request endpoint explicitly.
func WithPushedAuthorizationEndpoint(u string) Option {
	return func(c *config) { c.overrides.PushedAuthorization = u }
}

// WithIntrospectionEndpoint sets the RFC 7662 introspection endpoint
// explicitly.
func WithIntrospectionEndpoint(u string) Option {
	return func(c *config) { c.overrides.Introspection = u }
}

// WithEndSessionEndpoint sets the OpenID Connect RP-Initiated Logout
// end_session_endpoint explicitly.
func WithEndSessionEndpoint(u string) Option {
	return func(c *config) { c.overrides.EndSession = u }
}

// WithJWKSURL sets the JSON Web Key Set URL used to verify ID tokens.
func WithJWKSURL(u string) Option {
	return func(c *config) { c.overrides.JWKS = u }
}

// WithClientID sets the OAuth client identifier. Required.
func WithClientID(clientID string) Option {
	return func(c *config) { c.clientID = clientID }
}

// WithClientSecret sets the client secret. A secret compiled into a CLI
// that is distributed to users is not confidential; use one only for the
// client credentials grant in a controlled environment (CI, servers), or
// where a provider insists on one for installed apps (Google).
func WithClientSecret(secret string) Option {
	return func(c *config) { c.clientSecret = secret }
}

// WithAuthMethod selects the client authentication method. The default
// picks client_secret_basic when a secret is set (falling back to
// client_secret_post if discovery advertises only that), and none
// otherwise.
func WithAuthMethod(m ClientAuthMethod) Option {
	return func(c *config) { c.authMethod = m }
}

// WithClientAuthenticator installs a custom client authentication, such as
// mutual TLS or a key held in a hardware token. It replaces the built-in
// methods, [WithPrivateKeyJWT] included.
func WithClientAuthenticator(a ClientAuthenticator) Option {
	return func(c *config) { c.authenticator = a }
}

// WithPrivateKeyJWT authenticates the client with a JWT it signs with key
// (private_key_jwt, RFC 7523 § 2.2 and OIDC Core § 9) instead of a shared
// secret. keyID is the key's kid in the JWKS registered for the client; it
// may be empty when the server holds a single key. The algorithm follows
// from the key: ES256, ES384 or ES512 for ECDSA keys, EdDSA for Ed25519
// and RS256 for RSA (PS256 when the server advertises only that). A new
// assertion with a unique jti and a two-minute lifetime is minted for every
// request. Its audience is the issuer by default; see
// [WithAssertionAudience].
func WithPrivateKeyJWT(key crypto.Signer, keyID string) Option {
	return func(c *config) {
		c.assertionKey = key
		c.assertionKeyID = keyID
		c.authMethod = ClientAuthPrivateKeyJWT
	}
}

// WithAssertionAudience selects the aud claim of the client assertions
// [WithPrivateKeyJWT] and [ClientAuthSecretJWT] create. The default,
// [AssertionAudienceIssuer], follows the current guidance (RFC 7523bis and
// the OAuth 2.0 Security BCP); [AssertionAudienceTokenEndpoint] suits
// servers that still expect the token endpoint URL (OIDC Core § 9).
func WithAssertionAudience(a AssertionAudience) Option {
	return func(c *config) { c.assertionAud = a }
}

// WithDPoP binds every token to a key the client holds, with DPoP
// (RFC 9449). A new P-256 key (ES256) is generated for each login and
// stored with the tokens, so a DPoP-bound refresh token keeps working
// across runs. Token requests and, through [Client.Transport], resource
// requests carry a fresh proof each; server nonces (use_dpop_nonce) are
// handled with one retry. A login that comes back with a Bearer token
// fails with [ErrDPoPNotBound]. To use DPoP only where the server
// advertises it, use [WithDPoPAuto] instead.
func WithDPoP() Option {
	return func(c *config) { c.dpop = dpopRequired }
}

// WithDPoPAuto uses DPoP (see [WithDPoP]) when the server's metadata
// advertises dpop_signing_alg_values_supported, and Bearer tokens
// otherwise. A server that ignores the proof and issues a Bearer token is
// accepted, with a warning in the log.
func WithDPoPAuto() Option {
	return func(c *config) { c.dpop = dpopAuto }
}

// WithPAR selects when the browser flow pushes its authorization request
// to the server first (RFC 9126) and sends only the returned request_uri
// through the browser. The default, [PARIfRequired], pushes when the
// server's metadata sets require_pushed_authorization_requests.
func WithPAR(mode PARMode) Option {
	return func(c *config) { c.par = mode }
}

// WithEndSession makes [Client.Logout] end the user's session at the
// provider too (OpenID Connect RP-Initiated Logout 1.0), when the provider
// has an end_session_endpoint: it prints the logout URL and opens it in the
// browser when one is usable. The stored ID token is sent as id_token_hint
// only when opts.IDTokenHint is set, and post_logout_redirect_uri only when
// opts.PostLogoutRedirectURI is.
func WithEndSession(opts EndSessionOptions) Option {
	return func(c *config) {
		o := opts
		c.endSession = &o
	}
}

// WithScopes sets the scopes to request, replacing the defaults (openid and
// offline_access for the user flows, none for client credentials). Request
// only what the CLI needs.
func WithScopes(scopes ...string) Option {
	return func(c *config) {
		c.scopes = append([]string(nil), scopes...)
		c.scopesSet = true
	}
}

// WithAudience sets the audience parameter (Auth0 and others use it to pick
// the API the access token is for). It is sent with the authorization
// request, the device authorization request and the client credentials
// token request; code redemption, device polling and refresh do not repeat
// it, since the grant already carries it. Tokens are stored per audience.
func WithAudience(audience string) Option {
	return func(c *config) { c.audience = audience }
}

// WithResource sets RFC 8707 resource indicators: the absolute URIs of the
// APIs the access token is for. They are sent to the authorization, PAR,
// device authorization and token endpoints, on refresh too. Tokens are
// stored per audience and resource set, so one CLI can hold tokens for
// several APIs side by side. A server that does not know a resource
// answers invalid_target ([ErrInvalidTarget]).
func WithResource(resources ...string) Option {
	return func(c *config) { c.resources = append([]string(nil), resources...) }
}

// WithAuthParam adds a parameter to the authorization request (browser
// flow) and the device authorization request, for provider extensions such
// as prompt or access_type. Parameters the flow sets itself win.
func WithAuthParam(key, value string) Option {
	return func(c *config) {
		if c.authParams == nil {
			c.authParams = url.Values{}
		}
		c.authParams.Add(key, value)
	}
}

// WithTokenParam adds a parameter to every token endpoint request.
// Parameters the grant sets itself win.
func WithTokenParam(key, value string) Option {
	return func(c *config) {
		if c.tokenParams == nil {
			c.tokenParams = url.Values{}
		}
		c.tokenParams.Add(key, value)
	}
}

// WithFlow selects the login flow. The default is [FlowAuto].
func WithFlow(f Flow) Option {
	return func(c *config) { c.flow = f }
}

// WithRedirectHost sets the host of the loopback redirect URI:
// "127.0.0.1" (default, RFC 8252 § 7.3), "[::1]" or "localhost" for
// providers that only accept that name. The listener always binds a
// loopback address.
func WithRedirectHost(host string) Option {
	return func(c *config) { c.redirectHost = host }
}

// WithRedirectPort sets a fixed port for the loopback redirect, for
// providers that match the redirect URI including its port. The default 0
// picks a free ephemeral port.
func WithRedirectPort(port int) Option {
	return func(c *config) { c.redirectPort = port }
}

// WithRedirectPath sets the path of the loopback redirect URI. The default
// is "/callback".
func WithRedirectPath(path string) Option {
	return func(c *config) { c.redirectPath = path }
}

// WithLoginTimeout bounds how long the browser flow waits for the redirect.
// The device flow is bounded by the server's expires_in instead.
func WithLoginTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.loginTimeout = d
		}
	}
}

// WithBrowser forces opening the browser on (true) or off (false). By
// default it is opened unless the session looks headless (SSH, no display).
// The URL is always printed as well.
func WithBrowser(open bool) Option {
	return func(c *config) {
		if open {
			c.browser = browserOn
		} else {
			c.browser = browserOff
		}
	}
}

// WithBrowserOpener replaces the function that opens URLs in a browser.
func WithBrowserOpener(open BrowserOpener) Option {
	return func(c *config) { c.openBrowser = open }
}

// WithQRCode prints a QR code of verification_uri_complete in the device
// flow, when the server sends one, so a phone can scan it.
func WithQRCode(enabled bool) Option {
	return func(c *config) { c.qrCode = enabled }
}

// WithDeviceAuthorizationHandler replaces the terminal prompt of the device
// flow, for custom UIs and tests.
func WithDeviceAuthorizationHandler(h DeviceAuthorizationHandler) Option {
	return func(c *config) { c.deviceHandler = h }
}

// WithRevokeOnLogout controls whether [Client.Logout] revokes the tokens at
// the server (RFC 7009) before deleting them locally. Default true.
func WithRevokeOnLogout(revoke bool) Option {
	return func(c *config) { c.revokeOnLogout = revoke }
}

// WithIDTokenValidation turns verification of ID tokens off (false) or on
// (true, the default). With it off, an ID token is stored but its claims
// are not trusted for anything.
func WithIDTokenValidation(enabled bool) Option {
	return func(c *config) { c.verifyIDToken = enabled }
}

// WithClockSkew sets the leeway allowed when checking ID token times.
// Default 60 seconds.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.idTokenLeeway = d
		}
	}
}

// WithExpirySkew sets how long before its expiry an access token is treated
// as expired and refreshed. Default 30 seconds.
func WithExpirySkew(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.expirySkew = d
		}
	}
}

// WithInsecureHTTP allows plain-http endpoints on any host. For tests
// against local servers only: tokens and secrets then cross the network in
// clear text. Loopback http (localhost, 127.0.0.1, ::1) is allowed without
// it.
func WithInsecureHTTP() Option {
	return func(c *config) { c.insecureHTTP = true }
}

// WithHTTPClient sets the HTTP client for every request, so callers can
// configure proxies, custom CAs or mutual TLS. Redirects are never followed
// on back-channel POSTs, and only same-origin on discovery GETs, whatever
// the client's CheckRedirect says.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) { c.httpClient = hc }
}

// WithStorage sets where token sets are stored. The default is the system
// keyring under the application name (see [WithAppName]). When p also
// implements [storage.Locker], as the keyring and file providers do, the
// client locks it across processes while it refreshes.
func WithStorage(p storage.Provider) Option {
	return func(c *config) { c.storage = p }
}

// WithLocker sets the cross-process lock held while a token set is read,
// refreshed and stored again, so that parallel runs of the CLI never
// redeem the same refresh token twice (servers that rotate refresh tokens
// revoke the grant when that happens). By default the storage provider is
// used when it implements [storage.Locker]. Use it for a custom provider
// backed by shared storage, for example with [storage.NewFileLocker].
func WithLocker(l storage.Locker) Option {
	return func(c *config) { c.locker = l }
}

// WithAppName names the application. It is the keyring service name when
// no storage is configured, and part of the User-Agent. The commands
// default it to the root command's name.
func WithAppName(name string) Option {
	return func(c *config) { c.appName = name }
}

// WithOutput sets where user-facing messages go: out for data a script may
// capture (the token command, status), errOut for prompts and progress.
// The commands default them to the cobra command's OutOrStdout and
// ErrOrStderr. Library methods write nothing unless this is set.
func WithOutput(out, errOut io.Writer) Option {
	return func(c *config) {
		if out != nil {
			c.out = out
		}
		if errOut != nil {
			c.errOut = errOut
		}
	}
}

// WithLogger sets a structured logger for debug events (discovery, polling,
// refresh). Tokens, codes and secrets are never logged.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// WithClock sets the time source.
func WithClock(clk Clock) Option {
	return func(c *config) {
		if clk != nil {
			c.clock = clk
		}
	}
}

// WithEndpointMiddleware adds middleware around back-channel requests. The
// first one added is the outermost.
func WithEndpointMiddleware(mw ...EndpointMiddleware) Option {
	return func(c *config) { c.middleware = append(c.middleware, mw...) }
}

// WithUserAgent sets the User-Agent header of every request.
func WithUserAgent(ua string) Option {
	return func(c *config) { c.userAgent = ua }
}

func mergeEndpoints(dst *Endpoints, src Endpoints) {
	set := func(d *string, s string) {
		if s != "" {
			*d = s
		}
	}
	set(&dst.Authorization, src.Authorization)
	set(&dst.Token, src.Token)
	set(&dst.DeviceAuthorization, src.DeviceAuthorization)
	set(&dst.Revocation, src.Revocation)
	set(&dst.Introspection, src.Introspection)
	set(&dst.UserInfo, src.UserInfo)
	set(&dst.JWKS, src.JWKS)
	set(&dst.EndSession, src.EndSession)
	set(&dst.PushedAuthorization, src.PushedAuthorization)
}
