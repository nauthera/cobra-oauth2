package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func FetchClientCredentialsToken(ctx context.Context, config Config) (*AccessTokenResponse, error) {
	// Serialize the payload to form-encoded format
	payload := url.Values{
		"client_id":     []string{*config.ClientId},
		"client_secret": []string{*config.ClientSecret},
		"grant_type":    []string{ClientCredentials.String()},
		"scope":         []string{joinScopes(*config.Scopes)},
	}

	// Add optional audience
	if config.Audience != nil {
		payload.Set("audience", *config.Audience)
	}

	// Execute the HTTP request
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *config.TokenEndpoint, bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create HTTP request", ErrInternal)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrHTTPFailure, resp.Status)
	}

	// Parse the response body
	var tokenResponse AccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response body", ErrInternal)
	}

	return &tokenResponse, nil
}
