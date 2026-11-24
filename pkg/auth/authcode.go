package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// randomToken returns n bytes from crypto/rand, base64url-encoded without
// padding. 32 bytes give the 43-character PKCE verifier RFC 7636 § 4.1
// recommends, and 256 bits for state and nonce.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge returns the S256 code challenge for verifier
// (RFC 7636 § 4.2). The plain method is never used.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type callbackResult struct {
	code string
	err  error
}

const (
	callbackSuccessPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signed in</title></head>` +
		`<body style="font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;text-align:center">` +
		`<h1>You are signed in</h1><p>You can close this window and return to the terminal.</p></body></html>`
	callbackFailurePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>` +
		`<body style="font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;text-align:center">` +
		`<h1>Sign-in failed</h1><p>Return to the terminal for details.</p></body></html>`
)

// BrowserLogin runs the authorization code grant with PKCE (S256) and a
// loopback redirect URI (RFC 8252 § 7.3): it listens on a loopback port,
// sends the user's browser to the authorization endpoint (through a pushed
// authorization request when [WithPAR] or the server asks for one),
// validates state and the RFC 9207 iss parameter on the redirect, and
// redeems the code, with a DPoP proof when DPoP is in use. It returns the
// token set without storing it; [Client.Login] stores it.
func (c *Client) BrowserLogin(ctx context.Context) (*storage.Token, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if md.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: the provider has no authorization_endpoint; use the device flow", ErrUnsupportedFlow)
	}
	if _, err := c.usePAR(md); err != nil {
		return nil, err
	}
	key, err := c.loginDPoPKey(ctx, md)
	if err != nil {
		return nil, err
	}

	verifier, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	state, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	scopes := c.userScopes()
	nonce := ""
	if hasScope(scopes, "openid") {
		if nonce, err = randomToken(32); err != nil {
			return nil, err
		}
	}

	lns, port, err := c.listenLoopback(ctx)
	if err != nil {
		return nil, err
	}
	closeAll := func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}
	redirectURI := "http://" + c.cfg.redirectHost + ":" + strconv.Itoa(port) + c.cfg.redirectPath

	authURL, err := c.authorizationURL(ctx, md, authRequest{
		redirectURI: redirectURI, state: state, nonce: nonce,
		challenge: pkceChallenge(verifier), scopes: scopes, dpop: key,
	})
	if err != nil {
		closeAll()
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.loginTimeout)
	defer cancel()

	results := make(chan callbackResult, 1)
	srv := &http.Server{
		Handler:           c.callbackHandler(md, state, results),
		ReadHeaderTimeout: 10 * time.Second,
		// net/http logs handler panics and connection errors to os.Stderr
		// by default; send them to the configured logger instead.
		ErrorLog: slog.NewLogLogger(c.logger().Handler(), slog.LevelDebug),
	}
	serveErr := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { serveErr <- srv.Serve(ln) }()
	}
	defer func() {
		shutdownCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer done()
		_ = srv.Shutdown(shutdownCtx)
	}()

	w := c.cfg.errOut
	if c.tryOpenBrowser(ctx, authURL) {
		_, _ = fmt.Fprintf(w, "Opened your browser to sign in. If it did not open, visit:\n\n    %s\n\n", authURL)
	} else {
		_, _ = fmt.Fprintf(w, "Open this URL in a browser on this machine to sign in:\n\n    %s\n\n", authURL)
	}
	_, _ = fmt.Fprintln(w, "Waiting for the browser to finish signing in...")

	var res callbackResult
	select {
	case res = <-results:
	case err := <-serveErr:
		return nil, fmt.Errorf("loopback listener: %w", err)
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("browser login: no redirect within %s: %w", c.cfg.loginTimeout, ctx.Err())
		}
		return nil, fmt.Errorf("browser login: %w", ctx.Err())
	}
	if res.err != nil {
		return nil, res.err
	}
	return c.exchangeCode(ctx, md, res.code, redirectURI, verifier, nonce, strings.Join(scopes, " "), key)
}

// localhostListenAttempts bounds how often an ephemeral port is picked anew
// when its IPv6 twin is taken.
const localhostListenAttempts = 5

// listenLoopback binds the redirect listeners to loopback addresses only
// and returns them with their common port.
//
// For "localhost" the browser may connect to 127.0.0.1 or to ::1 (most
// prefer IPv6), so both are bound on the same port. Binding only one would
// leave the other free for any local process, of any user, to listen on and
// receive the authorization response, state and code included
// (RFC 8252 § 8.3). Where ::1 is not configured at all, no one can bind
// it and 127.0.0.1 alone suffices.
func (c *Client) listenLoopback(ctx context.Context) ([]net.Listener, int, error) {
	var lc net.ListenConfig
	listen := func(host string, port int) (net.Listener, int, error) {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil, 0, err
		}
		addr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			_ = ln.Close()
			return nil, 0, fmt.Errorf("loopback listener has unexpected address %s", ln.Addr())
		}
		return ln, addr.Port, nil
	}
	single := func(host string) ([]net.Listener, int, error) {
		ln, port, err := listen(host, c.cfg.redirectPort)
		if err != nil {
			return nil, 0, fmt.Errorf("listen for the browser redirect: %w", err)
		}
		return []net.Listener{ln}, port, nil
	}
	switch c.cfg.redirectHost {
	case "[::1]":
		return single("::1")
	case "localhost":
	default:
		return single("127.0.0.1")
	}

	var lastErr error
	for range localhostListenAttempts {
		ln4, port, err := listen("127.0.0.1", c.cfg.redirectPort)
		if err != nil {
			return nil, 0, fmt.Errorf("listen for the browser redirect: %w", err)
		}
		ln6, _, err := listen("::1", port)
		if err == nil {
			return []net.Listener{ln4, ln6}, port, nil
		}
		if !ipv6LoopbackAvailable(ctx) {
			return []net.Listener{ln4}, port, nil
		}
		_ = ln4.Close()
		lastErr = err
		if c.cfg.redirectPort != 0 {
			break
		}
	}
	return nil, 0, fmt.Errorf("listen for the browser redirect: the port is taken on ::1, "+
		"where the browser may send the redirect for localhost: %w", lastErr)
}

// ipv6LoopbackAvailable reports whether ::1 can be bound at all.
func ipv6LoopbackAvailable(ctx context.Context) bool {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// authRequest holds the per-login values of an authorization request.
type authRequest struct {
	redirectURI, state, nonce, challenge string
	scopes                               []string
	dpop                                 *dpopKey
}

// authorizationURL builds the authorization request (RFC 6749 § 4.1.1)
// with PKCE, state, nonce, resource indicators and dpop_jkt, keeping any
// query the endpoint already has. When PAR is in use the parameters are
// pushed to the server first and the URL carries only client_id and the
// request_uri (RFC 9126 § 4).
func (c *Client) authorizationURL(ctx context.Context, md *Metadata, ar authRequest) (string, error) {
	u, err := c.safeBrowserURL(md.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("authorization endpoint: %w", err)
	}
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.cfg.clientID)
	params.Set("redirect_uri", ar.redirectURI)
	params.Set("state", ar.state)
	params.Set("code_challenge", ar.challenge)
	params.Set("code_challenge_method", "S256")
	if len(ar.scopes) > 0 {
		params.Set("scope", strings.Join(ar.scopes, " "))
	}
	if ar.nonce != "" {
		params.Set("nonce", ar.nonce)
	}
	if c.cfg.audience != "" {
		params.Set("audience", c.cfg.audience)
	}
	c.addResources(params)
	if ar.dpop != nil {
		// RFC 9449 § 10: bind the authorization code to the DPoP key.
		params.Set("dpop_jkt", ar.dpop.jkt)
	}
	addParams(params, c.cfg.authParams)

	push, err := c.usePAR(md)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if push {
		requestURI, err := c.pushAuthorizationRequest(ctx, md, params)
		if err != nil {
			return "", err
		}
		q.Set("client_id", c.cfg.clientID)
		q.Set("request_uri", requestURI)
	} else {
		for k, vs := range params {
			q[k] = vs
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// callbackHandler accepts exactly one redirect with the expected state on
// the redirect path. Requests with another path get 404; a wrong state gets
// an error page and the listener keeps waiting, so a stray or forged
// request cannot end the login.
func (c *Client) callbackHandler(md *Metadata, state string, results chan<- callbackResult) http.Handler {
	var (
		mu   sync.Mutex
		done bool
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		if r.URL.Path != c.cfg.redirectPath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			writePage(w, http.StatusBadRequest, callbackFailurePage)
			return
		}

		mu.Lock()
		first := !done
		done = true
		mu.Unlock()
		if !first {
			writePage(w, http.StatusBadRequest, callbackFailurePage)
			return
		}

		res := c.parseCallback(md, q)
		if res.err != nil {
			writePage(w, http.StatusBadRequest, callbackFailurePage)
		} else {
			writePage(w, http.StatusOK, callbackSuccessPage)
		}
		results <- res
	})
}

func writePage(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(page))
}

// parseCallback validates the authorization response (RFC 6749 § 4.1.2)
// after state matched: the RFC 9207 issuer, then error or code.
func (c *Client) parseCallback(md *Metadata, q url.Values) callbackResult {
	iss, hasIss := q["iss"]
	if md.AuthorizationResponseIssParameterSupported && !hasIss {
		return callbackResult{err: fmt.Errorf("%w: the authorization response has no iss parameter (RFC 9207)", ErrIssuerMismatch)}
	}
	if hasIss && (len(iss) != 1 || !c.issuerMatches(iss[0], md.Issuer)) {
		return callbackResult{err: fmt.Errorf("%w: the authorization response came from issuer %q, want %q",
			ErrIssuerMismatch, sanitize(strings.Join(iss, ","), maxURILen), md.Issuer)}
	}
	if code := q.Get("error"); code != "" {
		return callbackResult{err: fmt.Errorf("authorization: %w", newOAuthError(0, code, q.Get("error_description"), q.Get("error_uri")))}
	}
	code := q.Get("code")
	if code == "" {
		return callbackResult{err: fmt.Errorf("%w: the authorization response has no code", ErrInvalidResponse)}
	}
	return callbackResult{code: code}
}

// exchangeCode redeems the authorization code at the token endpoint
// (RFC 6749 § 4.1.3) with the PKCE verifier, and validates the ID token
// against the nonce.
func (c *Client) exchangeCode(ctx context.Context, md *Metadata, code, redirectURI, verifier, nonce, scope string, key *dpopKey) (*storage.Token, error) {
	form := url.Values{
		"grant_type":    {string(GrantAuthorizationCode)},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	c.addResources(form)
	addParams(form, c.cfg.tokenParams)
	resp, err := c.postFormDPoP(ctx, EndpointToken, md.TokenEndpoint, form, key)
	if err != nil {
		return nil, fmt.Errorf("redeem authorization code: %w", err)
	}
	tok, err := decodeTokenResponse(resp, c.now(), scope)
	if err != nil {
		return nil, fmt.Errorf("redeem authorization code: %w", err)
	}
	if err := c.bindDPoP(ctx, tok, key, true); err != nil {
		return nil, err
	}
	if err := c.checkIDToken(ctx, tok, nil, nonce); err != nil {
		return nil, err
	}
	return tok, nil
}
