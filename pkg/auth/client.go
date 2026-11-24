package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

const defaultAppName = "cobra-oauth2"

// Client is an OAuth 2.0 / OpenID Connect client for a command-line
// application. It discovers the authorization server lazily, runs the login
// flows, stores and refreshes the resulting tokens, and revokes them on
// logout. A Client is safe for concurrent use.
type Client struct {
	cfg        config
	postClient *http.Client // back-channel POSTs: never follows redirects
	getClient  *http.Client // discovery and JWKS: same-origin redirects only
	store      storage.Provider
	locker     storage.Locker // nil: no cross-process lock

	mdMu sync.Mutex
	md   *Metadata

	jwksMu sync.Mutex
	jwks   *jwksCache
	// refreshMu serializes renewing the token set within the process; the
	// locker does the same across processes.
	refreshMu sync.Mutex

	// cached is the token set last loaded or stored, so that a valid
	// access token is not read from storage (a keyring round trip, a
	// process spawn on macOS) for every request.
	cacheMu sync.Mutex
	cached  *storage.Token

	dpopMu      sync.Mutex
	dpopOrigins map[string]*dpopOrigin
	dpopCached  *dpopKey
}

// NewClient validates the options and returns a Client. It performs no
// network I/O: discovery happens on first use.
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	if cfg.appName == "" {
		cfg.appName = defaultAppName
	}
	if cfg.userAgent == defaultUserAgent && cfg.appName != defaultAppName {
		cfg.userAgent = cfg.appName + " " + defaultUserAgent
	}
	store := cfg.storage
	if store == nil {
		store = storage.NewKeyring(cfg.appName)
	}
	locker := cfg.locker
	if locker == nil {
		if l, ok := store.(storage.Locker); ok {
			locker = l
		}
	}
	return &Client{
		cfg:        cfg,
		postClient: noRedirectClient(hc),
		getClient:  sameOriginRedirectClient(hc),
		store:      store,
		locker:     locker,
	}, nil
}

func (cfg *config) validate() error {
	if cfg.optErr != nil {
		return cfg.optErr
	}
	if cfg.clientID == "" {
		return configErr("client ID is required (WithClientID)")
	}
	if cfg.issuer == "" && cfg.discoveryURL == "" && cfg.overrides.Token == "" && cfg.fallbacks.Token == "" {
		return configErr("set the issuer (WithIssuer), a discovery URL (WithDiscoveryURL) or the endpoints (WithTokenEndpoint)")
	}
	if cfg.issuer != "" {
		u, err := validateEndpoint("issuer", cfg.issuer, cfg.insecureHTTP)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		if u.RawQuery != "" || u.ForceQuery {
			return configErr("issuer must not have a query")
		}
	}
	if cfg.discoveryURL != "" {
		if _, err := validateEndpoint("discovery", cfg.discoveryURL, cfg.insecureHTTP); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	for name, ep := range map[string]string{
		"authorization":        cfg.overrides.Authorization,
		"token":                cfg.overrides.Token,
		"device_authorization": cfg.overrides.DeviceAuthorization,
		"revocation":           cfg.overrides.Revocation,
		"introspection":        cfg.overrides.Introspection,
		"userinfo":             cfg.overrides.UserInfo,
		"jwks":                 cfg.overrides.JWKS,
		"end_session":          cfg.overrides.EndSession,
		"pushed_authorization": cfg.overrides.PushedAuthorization,
	} {
		if ep == "" {
			continue
		}
		if _, err := validateEndpoint(name, ep, cfg.insecureHTTP); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	switch cfg.flow {
	case FlowAuto, FlowDevice, FlowBrowser, FlowClientCredentials:
	case "":
		cfg.flow = FlowAuto
	default:
		return configErr("unknown flow %q (want auto, device, browser or client-credentials)", cfg.flow)
	}
	switch cfg.authMethod {
	case ClientAuthAuto, ClientAuthNone:
	case ClientAuthSecretBasic, ClientAuthSecretPost, ClientAuthSecretJWT:
		if cfg.clientSecret == "" {
			return configErr("auth method %s needs a client secret (WithClientSecret)", cfg.authMethod)
		}
	case ClientAuthPrivateKeyJWT:
		if cfg.assertionKey == nil {
			return configErr("auth method %s needs a signing key (WithPrivateKeyJWT)", cfg.authMethod)
		}
	default:
		return configErr("unsupported auth method %q; use WithClientAuthenticator for custom methods", cfg.authMethod)
	}
	if cfg.assertionKey != nil {
		if _, err := assertionAlg(cfg.assertionKey, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	switch cfg.assertionAud {
	case AssertionAudienceIssuer, AssertionAudienceTokenEndpoint:
	default:
		return configErr("unknown assertion audience %q", cfg.assertionAud)
	}
	if cfg.flow == FlowClientCredentials && !cfg.confidential() {
		return configErr("the client credentials flow needs a client secret, a signing key or a client authenticator")
	}
	switch cfg.par {
	case PARIfRequired, PARIfAvailable, PARAlways:
	default:
		return configErr("unknown PAR mode %q", cfg.par)
	}
	for _, r := range cfg.resources {
		if err := validateResource(r); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	if cfg.endSession != nil && cfg.endSession.PostLogoutRedirectURI != "" {
		if _, err := validateEndpoint("post_logout_redirect_uri", cfg.endSession.PostLogoutRedirectURI, cfg.insecureHTTP); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	cfg.redirectHost = strings.ToLower(cfg.redirectHost)
	switch cfg.redirectHost {
	case "127.0.0.1", "[::1]", "localhost":
	case "::1":
		cfg.redirectHost = "[::1]"
	default:
		return configErr("redirect host %q is not a loopback host (127.0.0.1, [::1] or localhost)", cfg.redirectHost)
	}
	if cfg.redirectPort < 0 || cfg.redirectPort > 65535 {
		return configErr("redirect port %d out of range", cfg.redirectPort)
	}
	if cfg.providerName == "cognito" && cfg.flow == FlowBrowser && cfg.redirectPort == 0 {
		// Cognito compares callback URLs exactly, port included, so a
		// random port fails every login with a redirect mismatch.
		return configErr("Cognito needs a fixed redirect port: set WithRedirectPort to the port of the callback URL registered for the app client")
	}
	if !strings.HasPrefix(cfg.redirectPath, "/") || strings.ContainsAny(cfg.redirectPath, "?#") {
		return configErr("redirect path %q must start with / and have no query or fragment", cfg.redirectPath)
	}
	for _, s := range cfg.scopes {
		if s == "" || strings.ContainsAny(s, " \"\\") {
			return configErr("invalid scope %q", s)
		}
	}
	return nil
}

// String describes the client without its secret.
func (c *Client) String() string {
	return fmt.Sprintf("auth.Client{issuer=%q client_id=%q secret=%s}", c.storageIssuer(), c.cfg.clientID, redact(c.cfg.clientSecret))
}

// GoString implements fmt.GoStringer, so that %#v, which would otherwise
// print every field, the client secret and signing keys included, prints
// the same redacted description as String.
func (c *Client) GoString() string { return c.String() }

// LogValue implements slog.LogValuer without the secret.
func (c *Client) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("issuer", c.storageIssuer()),
		slog.String("client_id", c.cfg.clientID),
		slog.String("provider", c.cfg.providerName),
		slog.Bool("confidential", c.cfg.confidential()),
	)
}

// confidential reports whether the client has credentials of its own: a
// secret, a signing key or a custom authenticator.
func (cfg *config) confidential() bool {
	return cfg.clientSecret != "" || cfg.assertionKey != nil || cfg.authenticator != nil
}

// validateResource checks an RFC 8707 resource indicator: an absolute URI
// without a fragment.
func validateResource(r string) error {
	u, err := url.Parse(r)
	if err != nil {
		return fmt.Errorf("resource %q: %w", sanitize(r, maxURILen), err)
	}
	if !u.IsAbs() || u.Fragment != "" || strings.Contains(r, "#") {
		return fmt.Errorf("resource %q must be an absolute URI without a fragment", sanitize(r, maxURILen))
	}
	return nil
}

// addResources sets the RFC 8707 resource parameters in form.
func (c *Client) addResources(form url.Values) {
	if len(c.cfg.resources) > 0 {
		form["resource"] = append([]string(nil), c.cfg.resources...)
	}
}

// storageAudience combines the audience and the resource indicators into
// the Audience of the storage key, so tokens for different APIs are kept
// apart. The resources are sorted: their order does not change the token.
func (c *Client) storageAudience() string {
	if len(c.cfg.resources) == 0 {
		return c.cfg.audience
	}
	rs := slices.Compact(slices.Sorted(slices.Values(c.cfg.resources)))
	if c.cfg.audience != "" {
		rs = append([]string{c.cfg.audience}, rs...)
	}
	return strings.Join(rs, " ")
}

func redact(s string) string {
	if s == "" {
		return `""`
	}
	return "[redacted]"
}

func (c *Client) logger() *slog.Logger {
	if c.cfg.logger != nil {
		return c.cfg.logger
	}
	return slog.New(slog.DiscardHandler)
}

// storageIssuer names the authorization server for token storage without
// any network I/O: the configured issuer, the one a discovery URL implies,
// or the token endpoint when neither exists.
func (c *Client) storageIssuer() string {
	if c.cfg.issuer != "" {
		return c.cfg.issuer
	}
	if c.cfg.discoveryURL != "" {
		if iss, err := issuerFromDiscoveryURL(c.cfg.discoveryURL); err == nil {
			return iss
		}
		return c.cfg.discoveryURL
	}
	if c.cfg.overrides.Token != "" {
		return c.cfg.overrides.Token
	}
	return c.cfg.fallbacks.Token
}

// StorageKey returns the key the client's token set is stored under.
func (c *Client) StorageKey() storage.Key {
	return storage.Key{Issuer: c.storageIssuer(), ClientID: c.cfg.clientID, Audience: c.storageAudience()}
}

// Issuer returns the issuer identifier the client is configured for.
func (c *Client) Issuer() string { return c.storageIssuer() }

// userScopes returns the scopes requested by the user flows.
func (c *Client) userScopes() []string {
	switch {
	case c.cfg.scopesSet:
		return c.cfg.scopes
	case c.cfg.presetScopesSet:
		return c.cfg.presetScopes
	default:
		return defaultScopes
	}
}

func hasScope(scopes []string, s string) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

// addParams copies extra into form without overwriting what is set.
func addParams(form, extra url.Values) {
	for k, vs := range extra {
		if _, set := form[k]; set {
			continue
		}
		form[k] = append([]string(nil), vs...)
	}
}

// StoredToken returns the stored token set as it is, without refreshing it.
// It returns an error wrapping [ErrNotLoggedIn] when there is none.
func (c *Client) StoredToken(ctx context.Context) (*storage.Token, error) {
	key := c.StorageKey()
	tok, err := c.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%w (run the login command)", ErrNotLoggedIn)
		}
		return nil, fmt.Errorf("load token: %w", err)
	}
	return tok, nil
}

// save stores a token set under the client's key, stamping the key into it.
func (c *Client) save(ctx context.Context, tok *storage.Token) error {
	key := c.StorageKey()
	tok.Version = storage.CurrentVersion
	tok.Issuer, tok.ClientID, tok.Audience = key.Issuer, key.ClientID, key.Audience
	if err := c.store.Set(ctx, key, tok); err != nil {
		c.setCached(nil)
		return fmt.Errorf("store token: %w", err)
	}
	c.setCached(tok)
	return nil
}

// load reads the stored token set and remembers it.
func (c *Client) load(ctx context.Context) (*storage.Token, error) {
	tok, err := c.StoredToken(ctx)
	if err != nil {
		c.setCached(nil)
		return nil, err
	}
	c.setCached(tok)
	return tok, nil
}

func (c *Client) setCached(tok *storage.Token) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cached = tok.Clone()
}

// cachedValid returns a copy of the remembered token set if its access
// token is still valid, and nil otherwise.
func (c *Client) cachedValid() *storage.Token {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cached == nil || c.cached.Expired(c.now(), c.cfg.expirySkew) {
		return nil
	}
	return c.cached.Clone()
}

// lockStorage takes the cross-process lock for the client's token set, or
// does nothing when there is no locker.
func (c *Client) lockStorage(ctx context.Context) (func(), error) {
	if c.locker == nil {
		return func() {}, nil
	}
	unlock, err := c.locker.Lock(ctx, c.StorageKey())
	if err != nil {
		return nil, fmt.Errorf("lock token storage: %w", err)
	}
	return unlock, nil
}

// Login runs the configured flow, stores the resulting token set and
// returns it. With [FlowAuto] it picks the browser flow when a browser is
// usable and the provider has an authorization endpoint, and the device flow
// otherwise.
func (c *Client) Login(ctx context.Context) (*storage.Token, error) {
	flow, err := c.resolveFlow(ctx)
	if err != nil {
		return nil, err
	}
	var tok *storage.Token
	switch flow {
	case FlowDevice:
		tok, err = c.DeviceLogin(ctx)
	case FlowBrowser:
		tok, err = c.BrowserLogin(ctx)
	case FlowClientCredentials:
		tok, err = c.ClientCredentials(ctx)
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedFlow, flow)
	}
	if err != nil {
		return nil, err
	}
	// The flow may take minutes; the lock is held only while storing.
	unlock, err := c.lockStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.save(ctx, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// resolveFlow turns FlowAuto into a concrete flow.
func (c *Client) resolveFlow(ctx context.Context) (Flow, error) {
	if c.cfg.flow != FlowAuto {
		return c.cfg.flow, nil
	}
	md, err := c.Metadata(ctx)
	if err != nil {
		return "", err
	}
	hasAuthz := md.AuthorizationEndpoint != "" && md.SupportsGrant(GrantAuthorizationCode)
	hasDevice := md.DeviceAuthorizationEndpoint != "" && md.SupportsGrant(GrantDeviceCode)
	switch {
	case hasAuthz && c.browserUsable():
		return FlowBrowser, nil
	case hasDevice:
		return FlowDevice, nil
	case hasAuthz:
		return FlowBrowser, nil
	default:
		return "", fmt.Errorf("%w: the provider offers neither the device flow nor an authorization endpoint", ErrUnsupportedFlow)
	}
}

func (c *Client) now() time.Time { return c.cfg.clock.Now() }
