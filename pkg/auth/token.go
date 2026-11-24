package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// ClientCredentials obtains a token with the client credentials grant
// (RFC 6749 § 4.4). Only the scopes set with [WithScopes] are requested;
// there are no defaults for this grant. It returns the token set without
// storing it; [Client.Login] and [Client.Token] store it.
func (c *Client) ClientCredentials(ctx context.Context) (*storage.Token, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if !md.SupportsGrant(GrantClientCredentials) {
		return nil, fmt.Errorf("%w: the provider does not list client_credentials in grant_types_supported", ErrUnsupportedFlow)
	}
	form := url.Values{"grant_type": {string(GrantClientCredentials)}}
	scope := ""
	if c.cfg.scopesSet && len(c.cfg.scopes) > 0 {
		scope = strings.Join(c.cfg.scopes, " ")
		form.Set("scope", scope)
	}
	if c.cfg.audience != "" {
		form.Set("audience", c.cfg.audience)
	}
	c.addResources(form)
	addParams(form, c.cfg.tokenParams)
	key, err := c.loginDPoPKey(ctx, md)
	if err != nil {
		return nil, err
	}
	resp, err := c.postFormDPoP(ctx, EndpointToken, md.TokenEndpoint, form, key)
	if err != nil {
		return nil, fmt.Errorf("client credentials: %w", err)
	}
	tok, err := decodeTokenResponse(resp, c.now(), scope)
	if err != nil {
		return nil, fmt.Errorf("client credentials: %w", err)
	}
	if err := c.bindDPoP(ctx, tok, key, true); err != nil {
		return nil, err
	}
	return tok, nil
}

// Refresh exchanges the refresh token of tok for a new token set
// (RFC 6749 § 6), with a DPoP proof made with tok's key when it has one (a
// DPoP-bound refresh token stays bound to the key it was issued for). A
// refresh token in the response replaces the old one (rotation); when the
// response has none, the old one is kept. An ID token in the response is
// validated and must name the same subject. Refresh does not store the
// result; [Client.Token] does.
//
// Once the server has answered with a new token set, the old refresh token
// may already be spent. So when a later check of that answer fails,
// Refresh returns the new token set together with the error, and the
// caller must store it to keep the rotated refresh token:
//
//   - An ID token that fails validation (an error wrapping
//     [ErrInvalidIDToken]) is removed from the returned set.
//   - A DPoP-bound access token issued to a request without a proof is
//     removed, so the next use refreshes again.
//
// An ID token that cannot be checked at all, because the JWKS cannot be
// fetched for example, is not an error: the previous ID token is kept and
// a warning is logged, since the access token is unaffected.
//
// Do not retry a failed refresh with the same refresh token: servers that
// rotate refresh tokens treat reuse as theft and revoke the whole grant.
func (c *Client) Refresh(ctx context.Context, tok *storage.Token) (*storage.Token, error) {
	if tok == nil || tok.RefreshToken == "" {
		return nil, fmt.Errorf("%w: no refresh token", ErrLoginRequired)
	}
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	key, err := c.tokenDPoPKey(tok)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {string(GrantRefreshToken)},
		"refresh_token": {tok.RefreshToken},
	}
	c.addResources(form)
	addParams(form, c.cfg.tokenParams)
	resp, err := c.postFormDPoP(ctx, EndpointToken, md.TokenEndpoint, form, key)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	next, err := decodeTokenResponse(resp, c.now(), tok.Scope)
	if err != nil {
		if errors.Is(err, ErrInvalidGrant) {
			return nil, fmt.Errorf("%w: the refresh token was rejected: %w", ErrLoginRequired, err)
		}
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	// From here on the server has issued a new token set: never return
	// without it, or a rotated refresh token is lost.
	if next.RefreshToken == "" {
		next.RefreshToken = tok.RefreshToken
	}
	if err := c.bindDPoP(ctx, next, key, false); err != nil {
		next.AccessToken = ""
		next.IDToken = tok.IDToken
		return next, err
	}
	if next.IDToken == "" {
		next.IDToken = tok.IDToken
		return next, nil
	}
	if err := c.checkIDToken(ctx, next, tok, ""); err != nil {
		if !errors.Is(err, ErrInvalidIDToken) {
			c.logger().WarnContext(ctx, "could not validate the refreshed ID token; keeping the previous one", "error", err)
			next.IDToken = tok.IDToken
			return next, nil
		}
		next.IDToken = ""
		return next, err
	}
	return next, nil
}

// Token returns a usable token set: the stored one if its access token is
// still valid, otherwise a refreshed one, which is stored before it is
// returned. With [FlowClientCredentials] a missing or expired token is
// replaced by a new one from the client credentials grant.
//
// A valid token set is remembered, so repeated calls do not read storage
// each time. Renewal happens under a lock shared with other processes (see
// [WithLocker]) and re-reads storage first, so a token set another run of
// the CLI renewed a moment ago is used instead of refreshing again.
//
// It returns an error wrapping [ErrNotLoggedIn] when nothing is stored, and
// [ErrLoginRequired] when the token cannot be renewed without the user.
func (c *Client) Token(ctx context.Context) (*storage.Token, error) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if tok := c.cachedValid(); tok != nil {
		return tok, nil
	}
	tok, err := c.load(ctx)
	switch {
	case errors.Is(err, ErrNotLoggedIn) && c.cfg.flow == FlowClientCredentials:
		return c.renewShared(ctx, "")
	case err != nil:
		return nil, err
	case !tok.Expired(c.now(), c.cfg.expirySkew):
		return tok, nil
	}
	return c.renewShared(ctx, tok.AccessToken)
}

// AccessToken returns a valid access token, refreshing it when needed.
func (c *Client) AccessToken(ctx context.Context) (string, error) {
	tok, err := c.Token(ctx)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// renewShared renews the token set under the cross-process lock. stale is
// the access token known to be unusable (expired, or rejected by a
// resource server), "" when nothing was stored. Storage is read again
// once the lock is held: when another process renewed the token set
// meanwhile, its result is used and the refresh token is not redeemed a
// second time. The caller holds refreshMu.
func (c *Client) renewShared(ctx context.Context, stale string) (*storage.Token, error) {
	unlock, err := c.lockStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	tok, err := c.load(ctx)
	if err != nil {
		if errors.Is(err, ErrNotLoggedIn) && c.cfg.flow == FlowClientCredentials {
			return c.renewClientCredentials(ctx)
		}
		return nil, err
	}
	if tok.AccessToken != stale && !tok.Expired(c.now(), c.cfg.expirySkew) {
		c.logger().DebugContext(ctx, "using a token set renewed by another process", "expiry", tok.Expiry)
		return tok, nil
	}
	return c.renewLocked(ctx, tok)
}

// renewLocked replaces an expired token set. The caller holds refreshMu
// and the storage lock.
func (c *Client) renewLocked(ctx context.Context, tok *storage.Token) (*storage.Token, error) {
	if tok.RefreshToken == "" {
		if c.cfg.flow == FlowClientCredentials {
			return c.renewClientCredentials(ctx)
		}
		return nil, fmt.Errorf("%w: the access token expired and there is no refresh token "+
			"(request the offline_access scope to get one)", ErrLoginRequired)
	}
	next, err := c.Refresh(ctx, tok)
	if next != nil {
		// Persist before use: with rotation the old refresh token is spent,
		// so the new one must be saved before anything else can fail, and
		// even when a later check of the response failed.
		if serr := c.save(ctx, next); serr != nil {
			if err != nil {
				return nil, fmt.Errorf("%w (the renewed token set could not be stored either: %w)", err, serr)
			}
			return nil, serr
		}
	}
	if err != nil {
		return nil, err
	}
	c.logger().DebugContext(ctx, "refreshed access token", "expiry", next.Expiry)
	return next, nil
}

func (c *Client) renewClientCredentials(ctx context.Context) (*storage.Token, error) {
	tok, err := c.ClientCredentials(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.save(ctx, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// forceRefresh renews the token after a resource server rejected
// rejectedAccess, unless another caller, in this process or another one,
// already replaced it.
func (c *Client) forceRefresh(ctx context.Context, rejectedAccess string) (*storage.Token, error) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if tok := c.cachedValid(); tok != nil && tok.AccessToken != rejectedAccess {
		return tok, nil
	}
	return c.renewShared(ctx, rejectedAccess)
}

// Transport returns an http.RoundTripper that authorizes requests with the
// client's access token: "Authorization: Bearer" (RFC 6750 § 2.1, never in
// the query or body), or for a DPoP-bound token "Authorization: DPoP" with
// a fresh DPoP proof bound to the token (RFC 9449 § 7). It refreshes the
// token when it is expired, and once more when the resource server answers
// 401 with error="invalid_token" and the request can be replayed. A
// resource server's use_dpop_nonce challenge is answered with one retry
// carrying its nonce. A nil base means http.DefaultTransport.
//
// The access token is sent only to the origins (scheme, host and port) the
// transport is bound to: those of [WithAllowedOrigins], else those of the
// http(s) resource indicators set with [WithResource], else the origin of
// the first request it carries. A request to any other origin fails with
// an error wrapping [ErrOriginNotAllowed]. A redirect to another origin is
// followed without the token, so an open redirect or a redirect to a
// signed CDN or storage URL cannot hand it to a third party. Plain http is
// refused for anything but a loopback host, unless [WithInsecureHTTP] is
// set. To stop following redirects altogether, set the http.Client's
// CheckRedirect.
func (c *Client) Transport(base http.RoundTripper, opts ...TransportOption) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &transport{c: c, base: base}
	var tc transportConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&tc)
		}
	}
	origins := tc.origins
	if !tc.set {
		for _, r := range c.cfg.resources {
			if u, err := url.Parse(r); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
				origins = append(origins, r)
			}
		}
	}
	for _, o := range origins {
		origin, err := parseOrigin(o)
		if err != nil {
			t.err = fmt.Errorf("%w: %w", ErrInvalidConfig, err)
			break
		}
		t.origins = append(t.origins, origin)
	}
	t.pinFirst = len(t.origins) == 0 && t.err == nil
	return t
}

// TransportOption configures [Client.Transport].
type TransportOption func(*transportConfig)

type transportConfig struct {
	origins []string
	set     bool
}

// WithAllowedOrigins sets the origins [Client.Transport] sends the access
// token to, as URLs ("https://api.example.com"; a path is ignored). It
// replaces the default, which is the origins of the resource indicators,
// or the origin of the first request.
func WithAllowedOrigins(origins ...string) TransportOption {
	return func(tc *transportConfig) {
		tc.origins = append(tc.origins, origins...)
		tc.set = true
	}
}

type transport struct {
	c    *Client
	base http.RoundTripper
	err  error // an invalid option, returned by every RoundTrip

	mu       sync.Mutex
	origins  []string
	pinFirst bool // bind to the origin of the first request
}

// parseOrigin returns the origin of a URL as scheme://host:port, with the
// default port filled in, so that equivalent spellings compare equal.
func parseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("allowed origin %q: %w", sanitize(raw, maxURILen), err)
	}
	o, ok := canonicalOrigin(u)
	if !ok {
		return "", fmt.Errorf("allowed origin %q must be an http or https URL with a host", sanitize(raw, maxURILen))
	}
	return o, nil
}

// canonicalOrigin is the origin of u with the default port made explicit;
// ok is false for anything but an http or https URL with a host.
func canonicalOrigin(u *url.URL) (string, bool) {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if port == "" {
			port = "80"
		}
	default:
		return "", false
	}
	return scheme + "://" + net.JoinHostPort(host, port), true
}

// authorizes reports whether req may carry the access token. A request
// that may not is an error, except a redirect, which is sent on without
// the token.
func (t *transport) authorizes(req *http.Request) (bool, error) {
	redirect := req.Response != nil
	origin, ok := canonicalOrigin(req.URL)
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrOriginNotAllowed, req.URL.Redacted())
	}
	if req.URL.Scheme == "http" && !t.c.cfg.insecureHTTP && !isLoopbackHost(req.URL.Hostname()) {
		if redirect {
			return false, nil
		}
		return false, fmt.Errorf("%w: refusing to send the access token over plain http to %s", ErrInsecureEndpoint, req.URL.Redacted())
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pinFirst && !redirect {
		t.origins, t.pinFirst = []string{origin}, false
	}
	if slices.Contains(t.origins, origin) {
		return true, nil
	}
	if redirect {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s (allowed: %s)", ErrOriginNotAllowed, origin, strings.Join(t.origins, ", "))
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.err != nil {
		closeRequestBody(req)
		return nil, t.err
	}
	ok, err := t.authorizes(req)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if !ok {
		// A redirect to another origin: follow it, without credentials.
		r := req.Clone(req.Context())
		r.Header.Del("Authorization")
		r.Header.Del(dpopHeader)
		return t.base.RoundTrip(r)
	}
	ctx := req.Context()
	tok, err := t.c.Token(ctx)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := t.send(req, tok)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || !hasChallengeError(resp.Header, "invalid_token") {
		return resp, nil
	}
	replay, ok := replayable(req)
	if !ok {
		return resp, nil
	}
	// If the refresh fails, the server's 401 is returned as it is: it tells
	// most callers more than the refresh error, and they inspect the status.
	if fresh, rerr := t.c.forceRefresh(ctx, tok.AccessToken); rerr == nil {
		drainBody(resp)
		return t.send(replay, fresh)
	}
	return resp, nil
}

// send makes one authorized request, with the DPoP nonce retry for a
// DPoP-bound token.
func (t *transport) send(req *http.Request, tok *storage.Token) (*http.Response, error) {
	if tok.TokenType != TokenTypeDPoP {
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", TokenTypeBearer+" "+tok.AccessToken)
		return t.base.RoundTrip(r)
	}
	key, err := t.c.tokenDPoPKey(tok)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if key == nil {
		closeRequestBody(req)
		return nil, fmt.Errorf("%w: the DPoP-bound token has no key", ErrLoginRequired)
	}
	r, sent, err := t.c.dpopAuthorize(req, tok, key)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	newNonce, _ := t.c.observeDPoP(req.URL, resp.Header, sent)
	if resp.StatusCode != http.StatusUnauthorized || !newNonce ||
		!hasChallengeError(resp.Header, "use_dpop_nonce", "dpop") {
		return resp, nil
	}
	replay, ok := replayable(req)
	if !ok {
		return resp, nil
	}
	r2, sent2, err := t.c.dpopAuthorize(replay, tok, key)
	if err != nil {
		return resp, nil //nolint:nilerr // the server's 401 says more than a failure to sign the retry
	}
	drainBody(resp)
	resp2, err := t.base.RoundTrip(r2)
	if err != nil {
		return nil, err
	}
	t.c.observeDPoP(req.URL, resp2.Header, sent2)
	return resp2, nil
}

// dpopAuthorize returns a copy of req carrying a DPoP-bound access token
// and a proof for it, and the nonce the proof used.
func (c *Client) dpopAuthorize(req *http.Request, tok *storage.Token, key *dpopKey) (*http.Request, string, error) {
	proof, nonce, err := c.dpopProof(key, req.Method, req.URL, tok.AccessToken)
	if err != nil {
		return nil, "", err
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", TokenTypeDPoP+" "+tok.AccessToken)
	r.Header.Set(dpopHeader, proof)
	return r, nonce, nil
}

func drainBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))
	_ = resp.Body.Close()
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// replayable returns a copy of req with a fresh body, if it can be sent
// again.
func replayable(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	r := req.Clone(req.Context())
	r.Body = body
	return r, true
}

// Status summarizes the stored token set without any secret.
type Status struct {
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"client_id"`
	Subject         string    `json:"subject,omitempty"`
	Email           string    `json:"email,omitempty"`
	Name            string    `json:"name,omitempty"`
	TokenType       string    `json:"token_type"`
	Scope           string    `json:"scope,omitempty"`
	Expiry          time.Time `json:"expiry,omitzero"`
	Expired         bool      `json:"expired"`
	HasRefreshToken bool      `json:"has_refresh_token"`
}

// Status describes the stored token set. The identity comes from the ID
// token that was validated when it was stored. It does not refresh.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	tok, err := c.StoredToken(ctx)
	if err != nil {
		return nil, err
	}
	st := &Status{
		Issuer:    tok.Issuer,
		ClientID:  tok.ClientID,
		TokenType: tok.TokenType,
		// Sanitized again for a record stored by an older version.
		Scope:           sanitize(tok.Scope, maxScopeLen),
		Expiry:          tok.Expiry,
		Expired:         tok.Expired(c.now(), 0),
		HasRefreshToken: tok.RefreshToken != "",
	}
	if tok.IDToken != "" {
		if claims, err := unverifiedClaims(tok.IDToken); err == nil {
			st.Subject = sanitize(claims.Subject, maxURILen)
			st.Email = sanitize(claims.Email, maxURILen)
			st.Name = sanitize(claims.Name, maxURILen)
			if st.Name == "" {
				st.Name = sanitize(claims.PreferredUsername, maxURILen)
			}
		}
	}
	return st, nil
}
