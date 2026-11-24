package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// PARMode selects when the browser flow uses pushed authorization requests
// (RFC 9126).
type PARMode string

// PAR modes.
const (
	// PARIfRequired pushes the authorization request only when the
	// server's metadata sets require_pushed_authorization_requests. The
	// default.
	PARIfRequired PARMode = ""
	// PARIfAvailable pushes whenever the server has a
	// pushed_authorization_request_endpoint. The request's parameters then
	// never pass through the browser, its history or its extensions.
	PARIfAvailable PARMode = "if-available"
	// PARAlways always pushes, and fails when the server has no PAR
	// endpoint.
	PARAlways PARMode = "always"
)

// usePAR decides whether this authorization request is pushed.
func (c *Client) usePAR(md *Metadata) (bool, error) {
	has := md.PushedAuthorizationRequestEndpoint != ""
	switch {
	case md.RequirePushedAuthorizationRequests || c.cfg.par == PARAlways:
		if !has {
			return false, fmt.Errorf("%w: pushed authorization requests (RFC 9126) are required, "+
				"but the provider has no pushed_authorization_request_endpoint", ErrUnsupportedFlow)
		}
		return true, nil
	case c.cfg.par == PARIfAvailable:
		return has, nil
	default:
		return false, nil
	}
}

// pushAuthorizationRequest posts the authorization request parameters to
// the PAR endpoint with client authentication (RFC 9126 § 2.1) and returns
// the request_uri to send through the browser in their place.
func (c *Client) pushAuthorizationRequest(ctx context.Context, md *Metadata, params url.Values) (string, error) {
	form := cloneValues(params)
	// § 2.1: request_uri must not be pushed; it is what the push returns.
	form.Del("request_uri")
	resp, err := c.postForm(ctx, EndpointPushedAuthorization, md.PushedAuthorizationRequestEndpoint, form)
	if err != nil {
		return "", fmt.Errorf("pushed authorization request: %w", err)
	}
	fields, err := checkResponse("pushed_authorization", resp)
	if err != nil {
		return "", fmt.Errorf("pushed authorization request: %w", err)
	}
	requestURI := stringField(fields, "request_uri")
	if requestURI == "" || len(requestURI) > maxURILen || strings.ContainsAny(requestURI, " \t\r\n") {
		return "", fmt.Errorf("%w: pushed authorization response has no usable request_uri", ErrInvalidResponse)
	}
	return requestURI, nil
}
