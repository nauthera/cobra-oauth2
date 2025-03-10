package auth

import "errors"

var (
	ErrInvalidConfig        = errors.New("invalid configuration: missing required fields")
	ErrHTTPFailure          = errors.New("failed to connect to OAuth2 provider")
	ErrInvalidResponse      = errors.New("received invalid response from OAuth2 provider")
	ErrMissingResponseData  = errors.New("missing required data in the device authorization response")
	ErrAuthorizationPending = errors.New("authorization pending: user has not authorized yet")
	ErrSlowDown             = errors.New("polling too frequently: slow down")
	ErrTokenExpired         = errors.New("device code expired: user did not authorize in time")
	ErrUserDenied           = errors.New("user denied authorization")
	ErrInvalidTokenResponse = errors.New("malformed token response")
	ErrInvalidScope         = errors.New("invalid scope requested")
	ErrFileSaveFailed       = errors.New("failed to save token: permission denied")
	ErrInternal             = errors.New("internal library error")
)
