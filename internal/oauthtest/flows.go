package oauthtest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type authCode struct {
	clientID, redirectURI, challenge, nonce, scope, jkt string
	expires                                             time.Time
	used                                                bool
}

type pushedRequest struct {
	clientID string
	params   url.Values
	expires  time.Time
	used     bool
}

type deviceSession struct {
	clientID, userCode, scope, jkt string
	expires, lastPoll              time.Time
	interval                       time.Duration
	polls                          int
	decided                        *DeviceStep
	consumed                       bool
}

type accessToken struct {
	clientID, scope, jkt string
	expires              time.Time
	family               int
	revoked              bool
}

type refreshToken struct {
	clientID, scope, jkt string
	family               int
	spent                bool
}

// loopbackHost reports whether host is a loopback name or address.
func loopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// registeredRedirect matches a redirect URI exactly against the registered
// ones, except that a loopback http URI may differ by port (RFC 8252 § 7.3).
// It returns the URL to redirect to, built from the registered URI so that
// nothing from the request but a numeric loopback port reaches it.
func registeredRedirect(c *Client, raw string) (*url.URL, bool) {
	got, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	for _, reg := range c.RedirectURIs {
		want, err := url.Parse(reg)
		if err != nil {
			continue
		}
		if reg == raw {
			return want, true
		}
		if got.Scheme != "http" || !loopbackHost(got.Hostname()) {
			continue
		}
		if want.Scheme != got.Scheme || want.Hostname() != got.Hostname() || want.Path != got.Path || want.RawQuery != got.RawQuery {
			continue
		}
		port, err := strconv.ParseUint(got.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, false
		}
		want.Host = net.JoinHostPort(want.Hostname(), strconv.FormatUint(port, 10))
		return want, true
	}
	return nil, false
}

// redirectOK reports whether raw matches a registered redirect URI.
func redirectOK(c *Client, raw string) bool {
	_, ok := registeredRedirect(c, raw)
	return ok
}

func (s *Server) grantAllowed(c *Client, grant string) bool {
	return len(c.Grants) == 0 || slices.Contains(c.Grants, grant)
}

// validAuthorizationParams checks the parameters of an authorization
// request, pushed or not, and returns an error code and description.
func (s *Server) validAuthorizationParams(c *Client, p url.Values) (code, desc string) {
	switch {
	case !redirectOK(c, p.Get("redirect_uri")):
		return "invalid_request", "redirect_uri is not registered"
	case p.Get("response_type") != "code":
		return "unsupported_response_type", "only code is supported"
	case p.Get("code_challenge_method") != "S256":
		// nauthera refuses an absent method instead of reading it as plain.
		return "invalid_request", "code_challenge_method must be S256"
	case len(p.Get("code_challenge")) != 43:
		return "invalid_request", "code_challenge must be a base64url SHA-256 digest"
	case p.Get("state") == "":
		return "invalid_request", "state is required"
	case !s.grantAllowed(c, "authorization_code"):
		return "unauthorized_client", "the client may not use the authorization code grant"
	}
	return "", ""
}

// serveAuthorize is the browser-facing authorization endpoint: it decides
// at once (Config.Consent) and redirects back with a code or an error.
func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := q
	if ru := q.Get("request_uri"); ru != "" {
		s.mu.Lock()
		pr := s.pushed[ru]
		ok := pr != nil && !pr.used && s.now().Before(pr.expires) && pr.clientID == q.Get("client_id")
		if ok {
			pr.used = true
			params = pr.params
		}
		s.mu.Unlock()
		if !ok {
			http.Error(w, "invalid_request_uri", http.StatusBadRequest)
			return
		}
	} else if s.requirePAR() {
		http.Error(w, "pushed authorization requests are required", http.StatusBadRequest)
		return
	}
	c := s.clientByID(params.Get("client_id"))
	var (
		redirect *url.URL
		ok       bool
	)
	if c != nil {
		redirect, ok = registeredRedirect(c, params.Get("redirect_uri"))
	}
	if !ok {
		// Never redirect to an unverified URI: show an error page.
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	resp := url.Values{}
	if st := params.Get("state"); st != "" {
		resp.Set("state", st)
	}
	switch {
	case s.cfg.Quirks.WrongIss:
		resp.Set("iss", "https://attacker.example")
	case !s.cfg.Quirks.OmitIss:
		resp.Set("iss", s.issuer)
	}
	if code, desc := s.validAuthorizationParams(c, params); code != "" {
		resp.Set("error", code)
		resp.Set("error_description", desc)
	} else if s.cfg.Consent != nil && !s.cfg.Consent(params) {
		resp.Set("error", "access_denied")
		resp.Set("error_description", "the user denied the request")
	} else {
		code := "code-" + randomString(16)
		s.mu.Lock()
		s.codes[code] = &authCode{
			clientID: c.ID, redirectURI: params.Get("redirect_uri"), challenge: params.Get("code_challenge"),
			nonce: params.Get("nonce"), scope: params.Get("scope"), jkt: params.Get("dpop_jkt"),
			// nauthera's default code lifetime.
			expires: s.now().Add(60 * time.Second),
		}
		s.mu.Unlock()
		resp.Set("code", code)
	}
	redirect.RawQuery = resp.Encode()
	// The target is built from a registered redirect URI (registeredRedirect).
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) requirePAR() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.metadata["require_pushed_authorization_requests"].(bool)
	return v
}

// OpenBrowser plays the user's browser: it follows the authorization URL
// through the server's redirect to the client's loopback listener. Its
// signature matches auth.BrowserOpener. It waits for the loopback page,
// whose status [Server.CallbackStatus] reports.
func (s *Server) OpenBrowser(ctx context.Context, authURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := s.Client().Do(req)
	if err != nil {
		s.t.Errorf("oauthtest: browser: %v", err)
		return nil
	}
	_ = resp.Body.Close()
	s.mu.Lock()
	s.callbackStatus = resp.StatusCode
	s.mu.Unlock()
	return nil
}

// servePAR implements pushed authorization requests (RFC 9126 § 2).
func (s *Server) servePAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := s.authenticateClient(w, r)
	if c == nil {
		return
	}
	if r.PostForm.Get("request_uri") != "" {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "request_uri must not be pushed")
		return
	}
	params := cloneValues(r.PostForm)
	params.Del("client_secret")
	params.Set("client_id", c.ID)
	if code, desc := s.validAuthorizationParams(c, params); code != "" {
		s.oauthError(w, http.StatusBadRequest, code, desc)
		return
	}
	ru := "urn:ietf:params:oauth:request_uri:" + randomString(16)
	s.mu.Lock()
	s.pushed[ru] = &pushedRequest{clientID: c.ID, params: params, expires: s.now().Add(5 * time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": ru, "expires_in": 300})
}

// serveDeviceAuthorization implements RFC 8628 § 3.1 and § 3.2.
func (s *Server) serveDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := s.authenticateClient(w, r)
	if c == nil {
		return
	}
	if !s.grantAllowed(c, "urn:ietf:params:oauth:grant-type:device_code") {
		s.oauthError(w, http.StatusBadRequest, "unauthorized_client", "the client may not use the device grant")
		return
	}
	jkt := r.PostForm.Get("dpop_jkt")
	if jkt != "" && len(jkt) != 43 {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "dpop_jkt is not a SHA-256 thumbprint")
		return
	}
	interval := s.cfg.DeviceInterval
	if interval == 0 {
		interval = 5
	}
	expiresIn := s.cfg.DeviceExpiresIn
	if expiresIn == 0 {
		expiresIn = 900
	}
	userCode := s.cfg.UserCode
	if userCode == "" {
		userCode = "WDJB-MJHT"
	}
	deviceCode := "device-" + randomString(32)
	now := s.now()
	s.mu.Lock()
	s.devices[deviceCode] = &deviceSession{
		clientID: c.ID, userCode: userCode, scope: r.PostForm.Get("scope"), jkt: jkt,
		expires: now.Add(time.Duration(expiresIn) * time.Second), lastPoll: now,
		interval: time.Duration(interval) * time.Second,
	}
	s.mu.Unlock()

	verification := s.cfg.VerificationURI
	if verification == "" {
		verification = "{{base}}/device"
	}
	verification, _ = s.expand(verification).(string)
	body := map[string]any{
		"device_code": deviceCode,
		"user_code":   userCode,
		"expires_in":  s.number(expiresIn),
		"interval":    s.number(interval),
	}
	if s.cfg.Quirks.VerificationURL {
		body["verification_url"] = verification
	} else {
		body["verification_uri"] = verification
	}
	if !s.cfg.Quirks.NoVerificationURIComplete {
		body["verification_uri_complete"] = verification + "?user_code=" + url.QueryEscape(userCode)
	}
	s.writeBody(w, http.StatusOK, body)
}

// ApproveDevice approves the pending device authorization with userCode,
// as the user would on the verification page; the next poll succeeds.
func (s *Server) ApproveDevice(userCode string) bool { return s.decideDevice(userCode, DeviceApprove) }

// DenyDevice denies the pending device authorization with userCode.
func (s *Server) DenyDevice(userCode string) bool { return s.decideDevice(userCode, DeviceDeny) }

func (s *Server) decideDevice(userCode string, step DeviceStep) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalize := func(c string) string {
		return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(c))
	}
	for _, d := range s.devices {
		if !d.consumed && normalize(d.userCode) == normalize(userCode) {
			st := step
			d.decided = &st
			return true
		}
	}
	return false
}

// serveToken is the token endpoint.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Client authentication runs before DPoP verification, as at nauthera.
	c := s.authenticateClient(w, r)
	if c == nil {
		return
	}
	grant := r.PostForm.Get("grant_type")
	if grant == "urn:ietf:params:oauth:grant-type:token-exchange" && !s.cfg.TokenExchange {
		// nauthera answers grants it does not implement this way.
		s.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "token exchange is not available")
		return
	}
	if !s.grantAllowed(c, grant) {
		s.oauthError(w, http.StatusBadRequest, "unauthorized_client", "the client may not use this grant")
		return
	}

	jkt := ""
	if s.cfg.DPoP.Enabled {
		var err error
		jkt, err = s.checkDPoP(r, "")
		var de *dpopError
		switch {
		case errors.Is(err, errNoProof):
			jkt = ""
		case errors.As(err, &de):
			if de.code == "use_dpop_nonce" {
				w.Header().Set("DPoP-Nonce", s.newNonce())
			}
			s.oauthError(w, http.StatusBadRequest, de.code, de.desc)
			return
		}
		if jkt != "" && s.cfg.DPoP.RequireNonce {
			w.Header().Set("DPoP-Nonce", s.newNonce())
		}
	}

	switch grant {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, c, jkt)
	case "refresh_token":
		s.grantRefresh(w, r, c, jkt)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.grantDevice(w, r, c, jkt)
	case "client_credentials":
		if c.Secret == "" {
			s.oauthError(w, http.StatusBadRequest, "unauthorized_client", "a public client cannot use client credentials")
			return
		}
		s.issue(w, c.ID, r.PostForm.Get("scope"), jkt, "", false, false, 0)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.grantExchange(w, r, c, jkt)
	default:
		s.oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, c *Client, jkt string) {
	f := r.PostForm
	s.mu.Lock()
	ac := s.codes[f.Get("code")]
	valid := ac != nil && !ac.used && s.now().Before(ac.expires) && ac.clientID == c.ID
	if ac != nil {
		ac.used = true
	}
	s.mu.Unlock()
	if !valid {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or used code")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	switch {
	case f.Get("redirect_uri") != ac.redirectURI:
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
	case base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge:
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
	case ac.jkt != "" && ac.jkt != jkt:
		s.oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "the code is bound to another DPoP key")
	default:
		s.issue(w, c.ID, ac.scope, jkt, ac.nonce, true, true, 0)
	}
}

func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request, c *Client, jkt string) {
	if s.cfg.NoRefreshTokens {
		s.oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	raw := r.PostForm.Get("refresh_token")
	s.mu.Lock()
	rt := s.refresh[raw]
	if rt == nil || rt.clientID != c.ID || s.families[rt.family] {
		s.mu.Unlock()
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or revoked refresh token")
		return
	}
	if rt.spent {
		// Reuse of a rotated refresh token: treat it as theft.
		s.families[rt.family] = true
		s.mu.Unlock()
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	}
	if rt.jkt != "" && rt.jkt != jkt {
		s.mu.Unlock()
		s.oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "the refresh token is bound to another DPoP key")
		return
	}
	scope := rt.scope
	if req := r.PostForm.Get("scope"); req != "" {
		for _, sc := range requestScope(req) {
			if !slices.Contains(requestScope(rt.scope), sc) {
				s.mu.Unlock()
				s.oauthError(w, http.StatusBadRequest, "invalid_scope", "a refresh may only narrow the scope")
				return
			}
		}
		scope = req
	}
	if s.cfg.RefreshPolicy == RefreshRotate {
		rt.spent = true
	}
	family := rt.family
	s.mu.Unlock()

	switch s.cfg.RefreshPolicy {
	case RefreshReuse:
		s.issueWith(w, c.ID, scope, rt.jkt, "", false, true, family, raw)
	case RefreshOmit:
		s.issue(w, c.ID, scope, rt.jkt, "", false, true, family)
	default:
		s.issue(w, c.ID, scope, rt.jkt, "", true, true, family)
	}
}

func (s *Server) grantDevice(w http.ResponseWriter, r *http.Request, c *Client, jkt string) {
	now := s.now()
	s.mu.Lock()
	d := s.devices[r.PostForm.Get("device_code")]
	if d == nil || d.consumed || !now.Before(d.expires) {
		s.mu.Unlock()
		// nauthera collapses unknown, expired and used codes into this.
		s.oauthError(w, http.StatusBadRequest, "expired_token", "the device code is unknown or expired")
		return
	}
	if d.clientID != c.ID {
		s.mu.Unlock()
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "the device code belongs to another client")
		return
	}
	if d.jkt != "" && d.jkt != jkt {
		s.mu.Unlock()
		s.oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "the device session is bound to another DPoP key")
		return
	}
	early := s.cfg.EnforceInterval && now.Sub(d.lastPoll) < d.interval
	d.lastPoll = now
	var step DeviceStep
	switch {
	case early:
		step = DeviceSlowDown
	case d.decided != nil:
		step = *d.decided
	case len(s.cfg.DeviceScript) == 0:
		step = DeviceApprove
	default:
		step = s.cfg.DeviceScript[min(d.polls, len(s.cfg.DeviceScript)-1)]
		d.polls++
	}
	if step == DeviceSlowDown {
		d.interval += 5 * time.Second
	}
	if step == DeviceApprove || step == DeviceDeny || step == DeviceExpire {
		d.consumed = true
	}
	interval := int(d.interval / time.Second)
	scope, boundJKT := d.scope, d.jkt
	s.mu.Unlock()

	switch step {
	case DevicePending:
		s.oauthError(w, http.StatusBadRequest, "authorization_pending", "")
	case DeviceSlowDown:
		if s.cfg.Quirks.SlowDownInterval {
			s.writeBody(w, s.errorStatus("slow_down", http.StatusBadRequest), map[string]any{
				"error": "slow_down", "error_description": "too many requests", "interval": s.number(interval),
			})
			return
		}
		s.oauthError(w, http.StatusBadRequest, "slow_down", "")
	case DeviceDeny:
		s.oauthError(w, http.StatusBadRequest, "access_denied", "the user denied the request")
	case DeviceExpire:
		s.oauthError(w, http.StatusBadRequest, "expired_token", "the device code expired")
	default:
		if boundJKT != "" {
			jkt = boundJKT
		}
		s.issue(w, c.ID, scope, jkt, "", true, true, 0)
	}
}

func (s *Server) errorStatus(code string, def int) int {
	if st, ok := s.cfg.Quirks.ErrorStatus[code]; ok {
		return st
	}
	if st, ok := s.cfg.Quirks.ErrorStatus["*"]; ok {
		return st
	}
	return def
}

func (s *Server) grantExchange(w http.ResponseWriter, r *http.Request, c *Client, jkt string) {
	f := r.PostForm
	s.mu.Lock()
	subject := s.access[f.Get("subject_token")]
	s.mu.Unlock()
	if f.Get("subject_token_type") == "" || subject == nil || subject.revoked {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "the subject token is not valid")
		return
	}
	requested := f.Get("requested_token_type")
	if requested == "" {
		requested = "urn:ietf:params:oauth:token-type:access_token"
	}
	if requested != "urn:ietf:params:oauth:token-type:access_token" {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "issued-" + randomString(12), "token_type": "N_A",
			"issued_token_type": requested, "expires_in": 300,
		})
		return
	}
	s.issueWith(w, c.ID, f.Get("scope"), jkt, "", false, false, 0, "", map[string]any{"issued_token_type": requested})
}

// issue writes a successful token response. withRefresh asks for a new
// refresh token (subject to RefreshScope), withID for an ID token when the
// scope has openid; family 0 starts a new grant.
func (s *Server) issue(w http.ResponseWriter, clientID, scope, jkt, nonce string, withRefresh, withID bool, family int) {
	s.issueWith(w, clientID, scope, jkt, nonce, withRefresh, withID, family, "")
}

func (s *Server) issueWith(w http.ResponseWriter, clientID, scope, jkt, nonce string, withRefresh, withID bool,
	family int, keepRefresh string, extra ...map[string]any,
) {
	now := s.now()
	ttl := s.cfg.AccessTokenTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	scopes := requestScope(scope)
	at := "at-" + randomString(24)

	s.mu.Lock()
	if family == 0 {
		s.seq++
		family = s.seq
	}
	s.access[at] = &accessToken{clientID: clientID, scope: scope, jkt: jkt, expires: now.Add(ttl), family: family}
	rt := ""
	if withRefresh && !s.cfg.NoRefreshTokens && (s.cfg.RefreshScope == "" || slices.Contains(scopes, s.cfg.RefreshScope)) {
		rt = "rt-" + randomString(24)
		s.refresh[rt] = &refreshToken{clientID: clientID, scope: scope, jkt: jkt, family: family}
	}
	s.mu.Unlock()
	if keepRefresh != "" {
		rt = keepRefresh
	}

	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	} else if s.cfg.Quirks.TokenType != "" {
		tokenType = s.cfg.Quirks.TokenType
	}
	body := map[string]any{"access_token": at, "token_type": tokenType}
	if !s.cfg.Quirks.NoExpiresIn {
		body["expires_in"] = s.number(int(ttl / time.Second))
	}
	if rt != "" {
		body["refresh_token"] = rt
	}
	if scope != "" {
		sep := " "
		if s.cfg.Quirks.ScopeSeparator != "" {
			sep = s.cfg.Quirks.ScopeSeparator
		}
		body["scope"] = strings.Join(scopes, sep)
	}
	if withID && !s.cfg.NoIDTokens && slices.Contains(scopes, "openid") {
		body["id_token"] = s.idToken(clientID, nonce, now)
	}
	for k, v := range s.cfg.Quirks.ExtraTokenFields {
		body[k] = v
	}
	for _, e := range extra {
		for k, v := range e {
			body[k] = v
		}
	}
	s.writeBody(w, http.StatusOK, body)
}

// serveRevoke implements RFC 7009. Unknown tokens are not an error.
func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := s.authenticateClient(w, r)
	if c == nil {
		return
	}
	s.mu.Lock()
	if s.revokeFails > 0 {
		s.revokeFails--
		s.mu.Unlock()
		s.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again")
		return
	}
	tok := r.PostForm.Get("token")
	if rt := s.refresh[tok]; rt != nil && rt.clientID == c.ID {
		s.families[rt.family] = true
	}
	if at := s.access[tok]; at != nil && at.clientID == c.ID {
		at.revoked = true
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// Revoked reports whether token (an access or refresh token) can no longer
// be used: revoked, or part of a revoked grant.
func (s *Server) Revoked(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt := s.refresh[token]; rt != nil {
		return s.families[rt.family]
	}
	if at := s.access[token]; at != nil {
		return at.revoked || s.families[at.family]
	}
	return false
}

// serveIntrospect implements RFC 7662 for confidential clients only.
func (s *Server) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := s.authenticateClient(w, r)
	if c == nil {
		return
	}
	if c.Secret == "" {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "introspection needs a confidential client")
		return
	}
	now := s.now()
	s.mu.Lock()
	at := s.access[r.PostForm.Get("token")]
	active := at != nil && !at.revoked && !s.families[at.family] && now.Before(at.expires)
	s.mu.Unlock()
	if !active {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	tokenType := "Bearer"
	if at.jkt != "" {
		tokenType = "DPoP"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": true, "scope": at.scope, "client_id": at.clientID, "sub": s.subject(),
		"token_type": tokenType, "exp": at.expires.Unix(), "iat": now.Unix(), "iss": s.issuer,
		"aud": []any{s.issuer + "/api"},
	})
}

// serveUserInfo is a protected resource: it checks the access token, and
// for a DPoP-bound one the proof with ath and the nonce.
func (s *Server) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	now := s.now()
	s.mu.Lock()
	at := s.access[token]
	valid := at != nil && !at.revoked && !s.families[at.family] && now.Before(at.expires)
	s.mu.Unlock()
	challenge := func(scheme, code string) {
		params := `error="` + code + `"`
		if scheme == "DPoP" {
			params += `, algs="ES256"`
		}
		w.Header().Set("WWW-Authenticate", scheme+" "+params)
		w.WriteHeader(http.StatusUnauthorized)
	}
	switch {
	case !valid:
		challenge("Bearer", "invalid_token")
		return
	case at.jkt == "" && !strings.EqualFold(scheme, "Bearer"):
		challenge("Bearer", "invalid_token")
		return
	case at.jkt != "":
		if !strings.EqualFold(scheme, "DPoP") {
			challenge("DPoP", "invalid_token")
			return
		}
		jkt, err := s.checkDPoP(r, token)
		var de *dpopError
		if errors.As(err, &de) && de.code == "use_dpop_nonce" {
			w.Header().Set("DPoP-Nonce", s.newNonce())
			challenge("DPoP", "use_dpop_nonce")
			return
		}
		if err != nil || jkt != at.jkt {
			challenge("DPoP", "invalid_dpop_proof")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": s.subject(), "email": "user@example.com", "scope": at.scope})
}

// DeviceInterval returns the longest server-side polling interval of any
// device session, in seconds: what slow_down answers have grown it to.
func (s *Server) DeviceInterval() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := 0
	for _, d := range s.devices {
		if v := int(d.interval / time.Second); v > best {
			best = v
		}
	}
	return best
}
