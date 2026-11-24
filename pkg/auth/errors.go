package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Sentinel errors. An [*OAuthError] matches the sentinel for its error code
// with errors.Is, so callers can write errors.Is(err, auth.ErrAccessDenied)
// without caring whether the server said so in a JSON body or the library
// concluded it.
var (
	// ErrInvalidConfig means the options passed to [NewClient] do not form a
	// usable configuration.
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrInsecureEndpoint means an endpoint is not https (or loopback http).
	ErrInsecureEndpoint = errors.New("endpoint must use https")
	// ErrIssuerMismatch means a discovery document, an authorization
	// response or an ID token names a different issuer than the configured
	// one (RFC 8414 § 3.3, RFC 9207, OIDC Core § 3.1.3.7).
	ErrIssuerMismatch = errors.New("issuer mismatch")
	// ErrDiscovery means no usable discovery document was found.
	ErrDiscovery = errors.New("authorization server metadata discovery failed")
	// ErrUnsupportedFlow means the selected login flow is not available with
	// this configuration or provider.
	ErrUnsupportedFlow = errors.New("login flow not supported")
	// ErrInvalidResponse means a server response is malformed or misses a
	// required member.
	ErrInvalidResponse = errors.New("invalid response from authorization server")
	// ErrResponseTooLarge means a response body exceeded the size limit.
	ErrResponseTooLarge = errors.New("response body too large")
	// ErrStateMismatch means an authorization response carried the wrong
	// state value (RFC 6749 § 10.12).
	ErrStateMismatch = errors.New("authorization response state mismatch")
	// ErrInvalidIDToken means an ID token failed validation.
	ErrInvalidIDToken = errors.New("invalid ID token")
	// ErrNotLoggedIn means no token set is stored for this client.
	ErrNotLoggedIn = errors.New("not logged in")
	// ErrLoginRequired means the stored token set can no longer be used or
	// refreshed and the user must log in again.
	ErrLoginRequired = errors.New("login required")
	// ErrRevocationFailed is returned by [Client.Logout] when the local
	// token set was removed but revoking it at the server failed.
	ErrRevocationFailed = errors.New("token revocation failed")
	// ErrDPoPNotBound means DPoP was required ([WithDPoP]) but the server
	// issued a token that is not bound to the client's key.
	ErrDPoPNotBound = errors.New("the server did not bind the token to the DPoP key")
	// ErrIntrospectionUnsupported means the provider has no RFC 7662
	// introspection endpoint.
	ErrIntrospectionUnsupported = errors.New("the provider has no introspection endpoint")

	// ErrOriginNotAllowed is returned by the transport from
	// [Client.Transport] for a request to an origin it does not send the
	// access token to (see [WithAllowedOrigins]).
	ErrOriginNotAllowed = errors.New("the access token is not sent to this origin")

	// RFC 6749 § 5.2 and RFC 8628 § 3.5 error codes.

	// ErrInvalidRequest matches the invalid_request error code.
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrInvalidClient matches the invalid_client error code.
	ErrInvalidClient = errors.New("invalid_client")
	// ErrInvalidGrant matches the invalid_grant error code.
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrUnauthorizedClient matches the unauthorized_client error code.
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrUnsupportedGrantType matches the unsupported_grant_type error code.
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
	// ErrInvalidScope matches the invalid_scope error code.
	ErrInvalidScope = errors.New("invalid_scope")
	// ErrAccessDenied matches the access_denied error code: the user or the
	// server declined the request.
	ErrAccessDenied = errors.New("access_denied")
	// ErrAuthorizationPending matches the authorization_pending error code.
	ErrAuthorizationPending = errors.New("authorization_pending")
	// ErrSlowDown matches the slow_down error code.
	ErrSlowDown = errors.New("slow_down")
	// ErrExpiredToken matches the expired_token error code, and the device
	// code reaching its expires_in without approval.
	ErrExpiredToken = errors.New("expired_token")
	// ErrTemporarilyUnavailable matches the temporarily_unavailable code.
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
	// ErrUnsupportedTokenType matches the unsupported_token_type code
	// (RFC 7009 § 2.2.1).
	ErrUnsupportedTokenType = errors.New("unsupported_token_type")
	// ErrInvalidTarget matches the invalid_target code (RFC 8707 § 2,
	// RFC 8693 § 2.2.2): a resource or audience the server does not know or
	// the client may not use.
	ErrInvalidTarget = errors.New("invalid_target")
	// ErrInvalidDPoPProof matches the invalid_dpop_proof code (RFC 9449).
	ErrInvalidDPoPProof = errors.New("invalid_dpop_proof")
	// ErrUseDPoPNonce matches the use_dpop_nonce code (RFC 9449 § 8). The
	// client retries once with the server's nonce on its own, so this
	// surfaces only when the retry was refused too.
	ErrUseDPoPNonce = errors.New("use_dpop_nonce")
	// ErrInvalidRequestURI matches the invalid_request_uri code
	// (RFC 9126, OIDC Core § 3.1.2.6).
	ErrInvalidRequestURI = errors.New("invalid_request_uri")
)

var codeSentinels = map[string]error{
	"invalid_request":         ErrInvalidRequest,
	"invalid_client":          ErrInvalidClient,
	"invalid_grant":           ErrInvalidGrant,
	"unauthorized_client":     ErrUnauthorizedClient,
	"unsupported_grant_type":  ErrUnsupportedGrantType,
	"invalid_scope":           ErrInvalidScope,
	"access_denied":           ErrAccessDenied,
	"authorization_pending":   ErrAuthorizationPending,
	"slow_down":               ErrSlowDown,
	"expired_token":           ErrExpiredToken,
	"temporarily_unavailable": ErrTemporarilyUnavailable,
	"unsupported_token_type":  ErrUnsupportedTokenType,
	"invalid_target":          ErrInvalidTarget,
	"invalid_dpop_proof":      ErrInvalidDPoPProof,
	"use_dpop_nonce":          ErrUseDPoPNonce,
	"invalid_request_uri":     ErrInvalidRequestURI,
}

// OAuthError is an error response from an authorization server in the
// RFC 6749 § 5.2 format, or an error passed back to the redirect URI
// (§ 4.1.2.1).
//
// Description and URI come from the server. They are stripped of control
// characters and truncated before they are stored here, so printing an
// OAuthError to a terminal is safe.
type OAuthError struct {
	// Code is the error member, for example "invalid_grant".
	Code string
	// Description is the error_description member, if any.
	Description string
	// URI is the error_uri member, if any.
	URI string
	// StatusCode is the HTTP status of the response; 0 for an error
	// delivered through the browser redirect.
	StatusCode int
}

// Error implements error.
func (e *OAuthError) Error() string {
	var b strings.Builder
	b.WriteString("oauth2: ")
	b.WriteString(e.Code)
	if e.Description != "" {
		b.WriteString(": ")
		b.WriteString(e.Description)
	}
	if e.URI != "" {
		b.WriteString(" (")
		b.WriteString(e.URI)
		b.WriteString(")")
	}
	return b.String()
}

// Is reports whether target is the sentinel for e's error code.
func (e *OAuthError) Is(target error) bool {
	s, ok := codeSentinels[e.Code]
	return ok && s == target
}

// Retryable reports whether repeating the same request later may succeed:
// temporarily_unavailable, or a 5xx/429 status.
func (e *OAuthError) Retryable() bool {
	return e.Code == "temporarily_unavailable" || e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= 500
}

// DevicePending reports whether the error means "keep polling" in the
// device authorization grant (authorization_pending or slow_down).
func (e *OAuthError) DevicePending() bool {
	return e.Code == "authorization_pending" || e.Code == "slow_down"
}

func newOAuthError(status int, code, desc, uri string) *OAuthError {
	return &OAuthError{
		Code:        sanitize(code, maxCodeLen),
		Description: sanitize(desc, maxDescriptionLen),
		URI:         sanitize(uri, maxURILen),
		StatusCode:  status,
	}
}

// StatusError is an unexpected HTTP status without an OAuth error body. The
// body is deliberately not included: it is server-controlled and may be
// large, HTML, or echo request secrets.
type StatusError struct {
	StatusCode int
	// Endpoint names the endpoint that was called ("token", "discovery").
	Endpoint string
}

// Error implements error.
func (e *StatusError) Error() string {
	return fmt.Sprintf("%s endpoint returned HTTP %d %s", e.Endpoint, e.StatusCode, http.StatusText(e.StatusCode))
}

// Retryable reports whether the status suggests trying again later.
func (e *StatusError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

func configErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}
