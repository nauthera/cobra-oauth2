package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DeviceAuthResponse holds the response from the OAuth2 device code endpoint.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// FetchDeviceCode makes an HTTP POST request to the OAuth2 device code endpoint
// and retrieves the device code, user code, and verification URI.
func FetchDeviceCode(ctx context.Context, config Config) (*DeviceAuthResponse, error) {
	// Prepare the request payload
	payload := map[string]string{
		"client_id": config.ClientId,
		"scope":     joinScopes(config.Scopes),
	}

	// Add optional audience
	if config.Audience != "" {
		payload["audience"] = config.Audience
	}

	// Add optional client secret
	if config.ClientSecret != "" {
		payload["client_secret"] = config.ClientSecret
	}

	// Serialize the payload to form-encoded format
	formData := url.Values{}
	for key, value := range payload {
		formData.Set(key, value)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.DeviceAuthorizationEndpoint, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create HTTP request", ErrInternal)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute the HTTP request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return nil, fmt.Errorf("%w: invalid scope or client credentials", ErrInvalidScope)
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: invalid client ID or secret", ErrInvalidConfig)
		default:
			return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
		}
	}

	// Parse the response body
	var deviceAuth DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceAuth); err != nil {
		return nil, errors.Join(fmt.Errorf("%w: failed to decode response body", ErrInvalidResponse), err)
	}

	// Validate required fields in the response
	if deviceAuth.DeviceCode == "" || deviceAuth.UserCode == "" || deviceAuth.VerificationURI == "" {
		return nil, ErrMissingResponseData
	}

	// Return the parsed response
	return &deviceAuth, nil
}
