package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	revokeAttempts = 3
	revokeBackoff  = time.Second
)

// ErrRevocationUnsupported means the provider has no RFC 7009 revocation
// endpoint, so tokens can only be deleted locally.
var ErrRevocationUnsupported = errors.New("the provider has no revocation endpoint")

// Revoke revokes token at the revocation endpoint (RFC 7009). hint is
// "refresh_token" or "access_token". A server that answers 503 has not
// revoked the token yet, so the request is retried a few times with a
// backoff. unsupported_token_type is not an error: the token simply cannot
// be revoked by value (JWT access tokens on many servers).
func (c *Client) Revoke(ctx context.Context, token, hint string) error {
	md, err := c.Metadata(ctx)
	if err != nil {
		return err
	}
	if md.RevocationEndpoint == "" {
		return ErrRevocationUnsupported
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	var lastErr error
	for attempt := 0; attempt < revokeAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("revoke %s: %w", hint, ctx.Err())
			case <-c.cfg.clock.After(revokeBackoff << (attempt - 1)):
			}
		}
		resp, err := c.postForm(ctx, EndpointRevocation, md.RevocationEndpoint, form)
		if err != nil {
			return fmt.Errorf("revoke %s: %w", hint, err)
		}
		_, err = checkResponse("revocation", resp)
		if err == nil || errors.Is(err, ErrUnsupportedTokenType) {
			return nil
		}
		lastErr = fmt.Errorf("revoke %s: %w", hint, err)
		var oe *OAuthError
		var se *StatusError
		retry := (errors.As(err, &oe) && oe.Retryable()) ||
			(errors.As(err, &se) && se.StatusCode == http.StatusServiceUnavailable)
		if !retry {
			return lastErr
		}
	}
	return lastErr
}

// Logout revokes the stored tokens at the server when it supports RFC 7009
// (the refresh token first, which ends the whole grant on most servers,
// then the access token) and deletes them locally. Local deletion happens
// even when revocation fails; the error then wraps [ErrRevocationFailed],
// which callers may treat as a warning. With [WithEndSession] it then
// shows (and opens) the provider's logout URL, so the browser session ends
// too. With nothing stored it returns an error wrapping [ErrNotLoggedIn].
func (c *Client) Logout(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	// Hold the cross-process lock too, so a refresh in another process
	// cannot store a token set again after it was deleted here.
	unlock, err := c.lockStorage(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	c.setCached(nil)
	tok, err := c.StoredToken(ctx)
	if err != nil {
		return err
	}

	var revokeErr error
	if c.cfg.revokeOnLogout {
		revokeErr = c.revokeAll(ctx, tok.RefreshToken, tok.AccessToken)
	}
	if err := c.store.Delete(ctx, c.StorageKey()); err != nil {
		return fmt.Errorf("delete stored token: %w", err)
	}
	if c.cfg.endSession != nil {
		c.endSession(ctx, tok.IDToken)
	}
	if revokeErr != nil {
		return fmt.Errorf("%w: %w", ErrRevocationFailed, revokeErr)
	}
	return nil
}

func (c *Client) revokeAll(ctx context.Context, refresh, access string) error {
	md, err := c.Metadata(ctx)
	if err != nil {
		return err
	}
	if md.RevocationEndpoint == "" {
		return nil
	}
	var errs []error
	if refresh != "" {
		errs = append(errs, c.Revoke(ctx, refresh, "refresh_token"))
	}
	if access != "" {
		errs = append(errs, c.Revoke(ctx, access, "access_token"))
	}
	return errors.Join(errs...)
}
