package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestFetchConfigFromDiscoveryURL(t *testing.T) {
	tests := []struct {
		name           string
		discoveryURL   string
		responseBody   string
		responseStatus int
		expectError    bool
	}{
		{
			name:         "valid response",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			responseBody: `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/jwks"
			}`,
			responseStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "invalid JSON response",
			discoveryURL:   "http://example.com/.well-known/openid-configuration",
			responseBody:   `invalid json`,
			responseStatus: http.StatusOK,
			expectError:    true,
		},
		{
			name:           "HTTP error response",
			discoveryURL:   "http://example.com/.well-known/openid-configuration",
			responseBody:   `{"error": "not found"}`,
			responseStatus: http.StatusNotFound,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			discoveryURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("failed to parse server URL: %v", err)
			}

			metadata, err := FetchConfigFromDiscoveryURL(*discoveryURL)
			if (err != nil) != tt.expectError {
				t.Errorf("FetchConfigFromDiscoveryURL() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && metadata == nil {
				t.Errorf("expected metadata, got nil")
			}
		})
	}
}
