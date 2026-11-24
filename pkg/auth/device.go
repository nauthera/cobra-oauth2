package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

const (
	// defaultDeviceInterval is RFC 8628 § 3.2's default polling interval.
	defaultDeviceInterval = 5 * time.Second
	// slowDownStep is how much slow_down lengthens the interval (§ 3.5).
	slowDownStep = 5 * time.Second
	// maxErrorBackoff caps the backoff after transport errors and 5xx
	// answers. It never shortens the interval the server asked for.
	maxErrorBackoff    = 60 * time.Second
	defaultDeviceTTL   = 10 * time.Minute
	maxDeviceTTL       = 30 * time.Minute
	minDeviceTTLSlack  = time.Second
	deviceErrorBackoff = 2
)

var errDeviceCodeExpired = errors.New("device code expired")

// DeviceAuthorization is a pending device authorization (RFC 8628 § 3.2).
// The device code itself is kept unexported so it cannot be printed by
// accident (§ 5.4 of the RFC: only the user code is shown to the user).
type DeviceAuthorization struct {
	// UserCode is the code the user enters on the verification page.
	UserCode string
	// VerificationURI is the page where the user enters the code.
	VerificationURI string
	// VerificationURIComplete is the page with the code already filled in,
	// when the server provides one.
	VerificationURIComplete string
	// ExpiresAt is when the device code expires.
	ExpiresAt time.Time
	// Interval is the minimum time between polling requests.
	Interval time.Duration

	deviceCode string
	scope      string
	dpop       *dpopKey
}

// String implements fmt.Stringer without the device code.
func (da *DeviceAuthorization) String() string {
	return fmt.Sprintf("DeviceAuthorization{user_code=%q verification_uri=%q expires_at=%s}",
		da.UserCode, da.VerificationURI, da.ExpiresAt.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer without the device code.
func (da *DeviceAuthorization) GoString() string { return da.String() }

// StartDeviceAuthorization requests a device code and user code from the
// device authorization endpoint (RFC 8628 § 3.1).
func (c *Client) StartDeviceAuthorization(ctx context.Context) (*DeviceAuthorization, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if md.DeviceAuthorizationEndpoint == "" {
		// Never fall back to the authorization endpoint: it is a
		// browser-facing page, not a back-channel API for credentials.
		return nil, fmt.Errorf("%w: the provider does not advertise a device_authorization_endpoint; "+
			"set one with WithDeviceAuthorizationEndpoint or use the browser flow", ErrUnsupportedFlow)
	}
	if !md.SupportsGrant(GrantDeviceCode) {
		return nil, fmt.Errorf("%w: the provider does not list the device code grant in grant_types_supported", ErrUnsupportedFlow)
	}

	key, err := c.loginDPoPKey(ctx, md)
	if err != nil {
		return nil, err
	}

	scope := strings.Join(c.userScopes(), " ")
	form := url.Values{}
	if scope != "" {
		form.Set("scope", scope)
	}
	if c.cfg.audience != "" {
		form.Set("audience", c.cfg.audience)
	}
	c.addResources(form)
	if key != nil {
		// RFC 9449 § 10 binds the authorization to the key with dpop_jkt;
		// servers that support it then require proofs with that key when
		// the device code is redeemed.
		form.Set("dpop_jkt", key.jkt)
	}
	addParams(form, c.cfg.authParams)

	resp, err := c.postForm(ctx, EndpointDeviceAuthorization, md.DeviceAuthorizationEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	fields, err := checkResponse("device_authorization", resp)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	da, err := c.parseDeviceAuthorization(fields, scope)
	if err != nil {
		return nil, err
	}
	da.dpop = key
	return da, nil
}

func (c *Client) parseDeviceAuthorization(fields map[string]any, scope string) (*DeviceAuthorization, error) {
	if fields == nil {
		return nil, fmt.Errorf("%w: device authorization response is not JSON", ErrInvalidResponse)
	}
	da := &DeviceAuthorization{
		deviceCode: stringField(fields, "device_code"),
		UserCode:   stringField(fields, "user_code"),
		scope:      scope,
	}
	if da.deviceCode == "" || da.UserCode == "" {
		return nil, fmt.Errorf("%w: device authorization response lacks device_code or user_code", ErrInvalidResponse)
	}
	if !validUserCode(da.UserCode) {
		return nil, fmt.Errorf("%w: user_code contains characters that are unsafe to display", ErrInvalidResponse)
	}

	// verification_url is the pre-RFC spelling Google and Entra's v1
	// endpoint still send.
	rawURI := stringField(fields, "verification_uri")
	if rawURI == "" {
		rawURI = stringField(fields, "verification_url")
	}
	if rawURI == "" {
		return nil, fmt.Errorf("%w: device authorization response lacks verification_uri", ErrInvalidResponse)
	}
	u, err := c.safeBrowserURL(rawURI)
	if err != nil {
		return nil, fmt.Errorf("verification_uri: %w", err)
	}
	da.VerificationURI = u.String()
	if raw := stringField(fields, "verification_uri_complete"); raw != "" {
		if u, err := c.safeBrowserURL(raw); err == nil {
			da.VerificationURIComplete = u.String()
		}
	}

	ttl := defaultDeviceTTL
	if secs, ok := numberField(fields, "expires_in"); ok && secs > 0 {
		ttl = min(time.Duration(secs)*time.Second, maxDeviceTTL)
	}
	da.ExpiresAt = c.now().Add(ttl)
	da.Interval = defaultDeviceInterval
	if secs, ok := numberField(fields, "interval"); ok && secs > 0 {
		// RFC 8628 § 3.5: the client MUST wait at least this long between
		// polls, so it is a floor, never shortened. An interval longer
		// than the code lives is bounded by that lifetime: the single poll
		// then reports the code as expired.
		da.Interval = min(time.Duration(secs)*time.Second, ttl)
	}
	return da, nil
}

// PollDeviceAuthorization polls the token endpoint until the user approved
// or denied the request, the device code expired, or ctx is done
// (RFC 8628 § 3.4, § 3.5). It does not store the token set; [Client.Login]
// does.
func (c *Client) PollDeviceAuthorization(ctx context.Context, da *DeviceAuthorization) (*storage.Token, error) {
	if da == nil || da.deviceCode == "" {
		return nil, errors.New("poll device authorization: no pending authorization")
	}
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	remaining := da.ExpiresAt.Sub(c.now())
	ctx, cancel := context.WithTimeoutCause(ctx, max(remaining, minDeviceTTLSlack)+minDeviceTTLSlack, errDeviceCodeExpired)
	defer cancel()

	form := url.Values{
		"grant_type":  {string(GrantDeviceCode)},
		"device_code": {da.deviceCode},
	}
	c.addResources(form)
	addParams(form, c.cfg.tokenParams)

	interval := da.Interval
	for {
		select {
		case <-ctx.Done():
			return nil, deviceContextError(ctx)
		case <-c.cfg.clock.After(interval):
		}
		if !c.now().Before(da.ExpiresAt) {
			return nil, fmt.Errorf("%w: the code expired before it was approved", ErrExpiredToken)
		}

		resp, err := c.postFormDPoP(ctx, EndpointToken, md.TokenEndpoint, form, da.dpop)
		if err != nil {
			if ctx.Err() != nil {
				return nil, deviceContextError(ctx)
			}
			// A transport error (timeout, connection reset): back off and
			// keep polling, as RFC 8628 § 3.5 suggests.
			interval = errorBackoff(interval)
			c.logger().DebugContext(ctx, "device poll failed; backing off", "error", err, "interval", interval)
			continue
		}
		tok, err := decodeTokenResponse(resp, c.now(), da.scope)
		if err == nil {
			if err := c.bindDPoP(ctx, tok, da.dpop, true); err != nil {
				return nil, err
			}
			if err := c.checkIDToken(ctx, tok, nil, ""); err != nil {
				return nil, err
			}
			return tok, nil
		}

		var oe *OAuthError
		if errors.As(err, &oe) {
			switch oe.Code {
			case "authorization_pending":
				continue
			case "slow_down":
				interval = slowDownInterval(resp, interval)
				c.logger().DebugContext(ctx, "device poll: slow_down", "interval", interval)
				continue
			}
			return nil, fmt.Errorf("device authorization: %w", oe)
		}
		var se *StatusError
		if errors.As(err, &se) && se.Retryable() {
			interval = errorBackoff(interval)
			continue
		}
		return nil, fmt.Errorf("device authorization: %w", err)
	}
}

// slowDownInterval returns the interval after a slow_down: the interval
// the server sent with it (GitHub does), or the current one plus 5 seconds,
// whichever is longer (RFC 8628 § 3.5: the increase applies to all later
// requests). It is not capped: polling faster than the server asked earns
// another slow_down, and nauthera lengthens its own interval each time.
func slowDownInterval(resp *EndpointResponse, cur time.Duration) time.Duration {
	next := cur + slowDownStep
	if fields, err := parseFields(resp); err == nil {
		if secs, ok := numberField(fields, "interval"); ok {
			next = max(next, time.Duration(secs)*time.Second)
		}
	}
	return next
}

// errorBackoff doubles the interval after a failed poll, up to
// maxErrorBackoff, but never below the current interval, which is at
// least what the server asked for.
func errorBackoff(cur time.Duration) time.Duration {
	return max(cur, min(cur*deviceErrorBackoff, maxErrorBackoff))
}

func deviceContextError(ctx context.Context) error {
	if errors.Is(context.Cause(ctx), errDeviceCodeExpired) {
		return fmt.Errorf("%w: the code expired before it was approved", ErrExpiredToken)
	}
	return fmt.Errorf("device authorization: %w", ctx.Err())
}

// DeviceLogin runs the whole device flow: it starts the authorization,
// shows the user code and verification URI (or calls the configured
// DeviceAuthorizationHandler), and polls until the user decided. It returns
// the token set without storing it; [Client.Login] stores it.
func (c *Client) DeviceLogin(ctx context.Context) (*storage.Token, error) {
	da, err := c.StartDeviceAuthorization(ctx)
	if err != nil {
		return nil, err
	}
	if c.cfg.deviceHandler != nil {
		if err := c.cfg.deviceHandler(ctx, da); err != nil {
			return nil, fmt.Errorf("device authorization handler: %w", err)
		}
	} else {
		c.promptDevice(ctx, da)
	}
	return c.PollDeviceAuthorization(ctx, da)
}

// promptDevice prints the RFC 8628 § 3.3 user interaction to the error
// writer: always the verification URI and the user code, a QR code of the
// complete URI when enabled, and optionally the browser.
func (c *Client) promptDevice(ctx context.Context, da *DeviceAuthorization) {
	w := c.cfg.errOut
	_, _ = fmt.Fprintf(w, "To sign in, open this page in a browser on any device:\n\n    %s\n\n", da.VerificationURI)
	_, _ = fmt.Fprintf(w, "and enter the code:\n\n    %s\n\n", da.UserCode)
	if c.cfg.qrCode && da.VerificationURIComplete != "" {
		_, _ = fmt.Fprintln(w, "Or scan this QR code, which has the code filled in:")
		_, _ = fmt.Fprintln(w)
		qrterminal.GenerateHalfBlock(da.VerificationURIComplete, qrterminal.L, w)
		_, _ = fmt.Fprintln(w)
	}
	target := da.VerificationURIComplete
	if target == "" {
		target = da.VerificationURI
	}
	if c.tryOpenBrowser(ctx, target) {
		_, _ = fmt.Fprintln(w, "Opened the page in your browser. Check that the code shown there matches.")
	}
	_, _ = fmt.Fprintf(w, "Waiting for approval (the code expires at %s)...\n", da.ExpiresAt.Local().Format(time.Kitchen))
}
