package auth

import (
	"context"
	"errors"
	"fmt"
)

// ErrEndSessionUnsupported means the provider has no end_session_endpoint
// (OpenID Connect RP-Initiated Logout 1.0).
var ErrEndSessionUnsupported = errors.New("the provider has no end_session_endpoint")

// EndSessionOptions configures RP-initiated logout ([WithEndSession]).
type EndSessionOptions struct {
	// IDTokenHint sends the stored ID token as id_token_hint, which lets
	// the provider skip asking the user to confirm. The ID token then
	// appears in the printed URL and the browser's history.
	IDTokenHint bool
	// PostLogoutRedirectURI is where the provider sends the browser after
	// the logout. It must be registered for the client. Leave it empty to
	// let the provider show its own page, which suits a CLI.
	PostLogoutRedirectURI string
}

// EndSessionURL returns the provider's logout URL (OpenID Connect
// RP-Initiated Logout 1.0 § 2) with client_id, and id_token_hint and
// post_logout_redirect_uri as configured with [WithEndSession]. idToken is
// the ID token to send as the hint; it is ignored unless IDTokenHint is set.
// It returns an error wrapping [ErrEndSessionUnsupported] when the provider
// has no end_session_endpoint.
func (c *Client) EndSessionURL(ctx context.Context, idToken string) (string, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return "", err
	}
	if md.EndSessionEndpoint == "" {
		return "", ErrEndSessionUnsupported
	}
	u, err := c.safeBrowserURL(md.EndSessionEndpoint)
	if err != nil {
		return "", fmt.Errorf("end_session_endpoint: %w", err)
	}
	var opts EndSessionOptions
	if c.cfg.endSession != nil {
		opts = *c.cfg.endSession
	}
	q := u.Query()
	q.Set("client_id", c.cfg.clientID)
	if opts.IDTokenHint && idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	if opts.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", opts.PostLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// endSession shows the provider's logout URL after a local logout and
// opens it when a browser is usable. Without an end_session_endpoint it
// does nothing: the local logout already happened.
func (c *Client) endSession(ctx context.Context, idToken string) {
	u, err := c.EndSessionURL(ctx, idToken)
	if err != nil {
		c.logger().DebugContext(ctx, "no RP-initiated logout", "error", err)
		return
	}
	w := c.cfg.errOut
	if c.tryOpenBrowser(ctx, u) {
		_, _ = fmt.Fprintf(w, "Opened your browser to sign out of the provider too. If it did not open, visit:\n\n    %s\n\n", u)
		return
	}
	_, _ = fmt.Fprintf(w, "To sign out of the provider in your browser too, open:\n\n    %s\n\n", u)
}
