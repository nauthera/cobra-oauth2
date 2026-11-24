package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxBodySize bounds every response body this package reads.
	maxBodySize = 1 << 20
	// defaultHTTPTimeout is the per-request timeout of the default client.
	defaultHTTPTimeout = 30 * time.Second
	// maxDiscoveryRedirects bounds same-origin redirects on GET requests.
	maxDiscoveryRedirects = 3
	defaultUserAgent      = "cobra-oauth2"
)

// EndpointKind names the authorization server endpoint a request goes to.
type EndpointKind string

// Endpoint kinds passed to [ClientAuthenticator] and [EndpointMiddleware].
const (
	EndpointToken               EndpointKind = "token"
	EndpointDeviceAuthorization EndpointKind = "device_authorization"
	EndpointRevocation          EndpointKind = "revocation"
	EndpointPushedAuthorization EndpointKind = "pushed_authorization"
	EndpointIntrospection       EndpointKind = "introspection"
)

// EndpointRequest is a form-encoded POST about to be sent to a token,
// device authorization, revocation or other back-channel endpoint.
// Middleware and client authenticators may add form values and headers.
type EndpointRequest struct {
	Kind   EndpointKind
	URL    string
	Form   url.Values
	Header http.Header
}

// EndpointResponse is the bounded, fully read response to an
// [EndpointRequest].
type EndpointResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// EndpointHandler sends an [EndpointRequest]. Each call authenticates the
// client afresh, so a handler may be called more than once for one logical
// request (a retry with a new DPoP nonce, say) and every attempt carries
// fresh credentials such as a new client assertion.
type EndpointHandler func(ctx context.Context, req *EndpointRequest) (*EndpointResponse, error)

// EndpointMiddleware wraps the handler that sends back-channel requests. It
// is the extension point for sender-constrained tokens, request signing and
// similar decorations: modify req, call next, inspect or retry the response.
type EndpointMiddleware func(next EndpointHandler) EndpointHandler

// defaultHTTPClient returns the client used when none is configured: a
// 30-second timeout and TLS 1.2 or later.
func defaultHTTPClient() *http.Client {
	rt := http.DefaultTransport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t = t.Clone()
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else if t.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
		rt = t
	}
	return &http.Client{Timeout: defaultHTTPTimeout, Transport: rt}
}

// noRedirectClient returns a shallow copy of c that never follows redirects.
// OAuth back-channel endpoints are not expected to redirect, and following a
// 307/308 would replay the form body (client secret, device code, refresh
// token) to wherever the Location header points.
func noRedirectClient(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// sameOriginRedirectClient returns a shallow copy of c that follows at most
// a few redirects, and only to the same scheme and host. Used for GETs of
// public documents (discovery, JWKS), which some deployments redirect.
func sameOriginRedirectClient(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxDiscoveryRedirects {
			return errors.New("too many redirects")
		}
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			return fmt.Errorf("refusing cross-origin redirect to %s", req.URL.Redacted())
		}
		return nil
	}
	return &cp
}

// isLoopbackHost reports whether host (without port) is certain to reach
// this machine: a loopback address (127.0.0.0/8, ::1) or exactly the name
// localhost. It decides where back-channel requests may go over plain http.
//
// Names under .localhost are not included. Browsers map them to loopback,
// but Go's pure-Go resolver (the one a CGO_ENABLED=0 build uses) sends them
// to the configured DNS server, which could answer with a remote address.
// Credentials sent there over http would leave the machine in clear text.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// isLoopbackBrowserHost is isLoopbackHost plus any *.localhost name, for
// URLs only handed to the browser, which resolves those names to loopback
// itself (RFC 6761 § 6.3).
func isLoopbackBrowserHost(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	return strings.HasSuffix(strings.TrimSuffix(strings.ToLower(host), "."), ".localhost")
}

// validateEndpoint parses raw and checks it is fit to send credentials to:
// absolute, https (http only for a loopback host, or any host when
// allowInsecure is set for tests), with a host, and without userinfo or a
// fragment.
func validateEndpoint(name, raw string, allowInsecure bool) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s endpoint is empty", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s endpoint: %w", name, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure && !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%w: %s endpoint %s", ErrInsecureEndpoint, name, u.Redacted())
		}
	default:
		return nil, fmt.Errorf("%w: %s endpoint has scheme %q", ErrInsecureEndpoint, name, sanitize(u.Scheme, 16))
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%s endpoint %q: absolute URL with a host required", name, sanitize(raw, maxURILen))
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s endpoint: userinfo is not allowed in the URL", name)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s endpoint: a fragment is not allowed in the URL", name)
	}
	return u, nil
}

// readBody reads at most maxBodySize bytes and drains what is left (up to
// the same bound) so the connection can be reused. The caller closes it.
func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize)) }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(b) > maxBodySize {
		return nil, ErrResponseTooLarge
	}
	return b, nil
}

// postForm sends a back-channel request through the middleware chain.
func (c *Client) postForm(ctx context.Context, kind EndpointKind, endpoint string, form url.Values) (*EndpointResponse, error) {
	return c.postFormDPoP(ctx, kind, endpoint, form, nil)
}

// postFormDPoP sends a back-channel request with a DPoP proof made with key
// on every attempt, when key is not nil. The DPoP layer sits inside the
// configured middleware, so middleware sees the final response after any
// nonce retry.
func (c *Client) postFormDPoP(ctx context.Context, kind EndpointKind, endpoint string, form url.Values, key *dpopKey) (*EndpointResponse, error) {
	if _, err := validateEndpoint(string(kind), endpoint, c.cfg.insecureHTTP); err != nil {
		return nil, err
	}
	req := &EndpointRequest{Kind: kind, URL: endpoint, Form: cloneValues(form), Header: make(http.Header)}
	h := EndpointHandler(c.sendEndpointRequest)
	if key != nil {
		h = c.dpopMiddleware(key, h)
	}
	for i := len(c.cfg.middleware) - 1; i >= 0; i-- {
		h = c.cfg.middleware[i](h)
	}
	return h(ctx, req)
}

// sendEndpointRequest authenticates the client and sends one attempt.
func (c *Client) sendEndpointRequest(ctx context.Context, in *EndpointRequest) (*EndpointResponse, error) {
	// Authenticate a copy: a retry by middleware must start from the
	// unauthenticated request, not one that already carries credentials.
	req := &EndpointRequest{Kind: in.Kind, URL: in.URL, Form: cloneValues(in.Form), Header: in.Header.Clone()}
	auth, err := c.clientAuthenticator(ctx)
	if err != nil {
		return nil, err
	}
	if err := auth.Authenticate(ctx, req); err != nil {
		return nil, fmt.Errorf("client authentication: %w", err)
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, strings.NewReader(req.Form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", req.Kind, err)
	}
	for k, v := range req.Header {
		hreq.Header[k] = v
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("User-Agent", c.cfg.userAgent)

	resp, err := c.postClient.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", req.Kind, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("%s response: %w", req.Kind, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%s endpoint redirected (HTTP %d); refusing to follow", req.Kind, resp.StatusCode)
	}
	return &EndpointResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// getJSON fetches a public JSON document (discovery, JWKS) with a bounded
// body and same-origin redirects only.
func (c *Client) getJSON(ctx context.Context, name, endpoint string) (int, []byte, http.Header, error) {
	if _, err := validateEndpoint(name, endpoint, c.cfg.insecureHTTP); err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("build %s request: %w", name, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.cfg.userAgent)
	resp, err := c.getClient.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s request: %w", name, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readBody(resp)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s response: %w", name, err)
	}
	return resp.StatusCode, body, resp.Header, nil
}

// maxTransportErrorLen bounds the printed message of a failed request.
const maxTransportErrorLen = 1024

// redactURLError strips the query string from a *url.Error so a URL with
// embedded parameters never ends up in an error message, and makes the
// message safe to print (see [transportError]).
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			u.RawQuery = ""
			u.User = nil
			ue.URL = u.String()
		}
	}
	return &transportError{err: err}
}

// transportError is a request that failed before a response arrived. Its
// message can quote what the peer sent: a TLS failure lists the DNS names
// of the certificate presented (x509.HostnameError), which a network
// attacker chooses and which may hold terminal escape sequences. Error
// returns the message sanitized; Unwrap keeps the original for errors.Is
// and errors.As.
type transportError struct{ err error }

func (e *transportError) Error() string { return sanitize(e.err.Error(), maxTransportErrorLen) }

func (e *transportError) Unwrap() error { return e.err }

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
