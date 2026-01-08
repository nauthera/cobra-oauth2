package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func PollForAccessToken(ctx context.Context, config Config, deviceCode string, timeout time.Duration, interval time.Duration) (*AccessTokenResponse, error) {
	// Serialize the payload to form-encoded format
	payload := url.Values{
		"client_id":   []string{*config.ClientId},
		"device_code": []string{deviceCode},
		"grant_type":  []string{DeviceCode.String()},
	}

	if config.ClientSecret != nil {
		payload.Set("client_secret", *config.ClientSecret)
	}

	// Execute the HTTP request
	client := &http.Client{Timeout: 15 * time.Second}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var resp *http.Response
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: timed out waiting for user authorization", ErrTokenExpired)
		default:
			// Create HTTP request
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, *config.TokenEndpoint, bytes.NewBufferString(payload.Encode()))
			if err != nil {
				return nil, fmt.Errorf("%w: failed to create HTTP request", ErrInternal)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err = client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, err)
			}
			defer resp.Body.Close()
		}

		if resp.StatusCode == http.StatusOK {
			break
		}

		time.Sleep(interval)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return nil, fmt.Errorf("%w: %s", ErrInvalidTokenResponse, string(body))
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", ErrAuthorizationPending, string(body))
		case http.StatusForbidden:
			return nil, fmt.Errorf("%w: %s", ErrSlowDown, string(body))
		default:
			fmt.Printf("url: %s", *config.TokenEndpoint)
			return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
		}
	}

	// Parse the response body
	var tokenResponse AccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response body", ErrInternal)
	}

	return &tokenResponse, nil
}
