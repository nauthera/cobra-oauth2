package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPollForAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		serverStatus   int
		expectedError  error
	}{
		{
			name:           "Success",
			serverResponse: `{"access_token":"test_token","token_type":"bearer","expires_in":3600}`,
			serverStatus:   http.StatusOK,
			expectedError:  nil,
		},
		{
			name:           "BadRequest",
			serverResponse: `{"error":"invalid_request"}`,
			serverStatus:   http.StatusBadRequest,
			expectedError:  ErrTokenExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				if _, err := w.Write([]byte(tt.serverResponse)); err != nil {
					t.Fatalf("failed to write response: %v", err)
				}
			}))
			defer server.Close()

			config := Config{
				ClientId:      "test_client_id",
				ClientSecret:  "test_client_secret",
				TokenEndpoint: server.URL,
			}

			ctx := context.Background()
			deviceCode := "test_device_code"
			timeout := 5 * time.Second
			interval := 1 * time.Second

			_, err := PollForAccessToken(ctx, config, deviceCode, timeout, interval)
			if err != nil && tt.expectedError == nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if err == nil && tt.expectedError != nil {
				t.Fatalf("expected error %v, got none", tt.expectedError)
			}
			if err != nil && tt.expectedError != nil && errors.Unwrap(err).Error() != tt.expectedError.Error() {
				t.Fatalf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
