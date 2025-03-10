package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
	"github.com/stretchr/testify/assert"
)

func TestConfig_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				ClientId:                    "client_id",
				ClientSecret:                "client_secret",
				DeviceAuthorizationEndpoint: "https://example.com/device",
				TokenEndpoint:               "https://example.com/token",
				Scopes:                      []string{"scope1", "scope2"},
				StorageProvider:             storage.NewMemoryStorage("test"),
			},
			wantErr: false,
		},
		{
			name: "missing storage provider",
			config: Config{
				ClientId:                    "client_id",
				ClientSecret:                "client_secret",
				DeviceAuthorizationEndpoint: "https://example.com/device",
				TokenEndpoint:               "https://example.com/token",
				Scopes:                      []string{"scope1", "scope2"},
			},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: Config{
				ClientId:                    "client_id",
				ClientSecret:                "client_secret",
				DeviceAuthorizationEndpoint: "invalid-url",
				TokenEndpoint:               "https://example.com/token",
				Scopes:                      []string{"scope1", "scope2"},
				StorageProvider:             storage.NewMemoryStorage("test"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.IsValid()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if _, err := w.Write([]byte(`{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				 "device_authorization_endpoint": "https://example.com/device",
				"jwks_uri": "https://example.com/jwks"
			}`)); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}))
	defer server.Close()

	discoveryURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	metadata, err := FetchConfigFromDiscoveryURL(*discoveryURL)
	assert.NoError(t, err)

	config, err := configure(
		WithDiscoveryURL(*discoveryURL),
		WithClientID("client_id"),
		WithClientSecret("client_secret"),
		WithDeviceAuthorizationEndpoint("https://example.com/device"),
		WithTokenEndpoint("https://example.com/token"),
		WithScopes([]string{"scope1", "scope2"}),
		WithAudience("audience"),
		WithStorageProvider(storage.NewMemoryStorage("test")),
	)

	assert.NoError(t, err)
	assert.Equal(t, "client_id", config.ClientId)
	assert.Equal(t, "client_secret", config.ClientSecret)
	assert.Equal(t, "https://example.com/device", config.DeviceAuthorizationEndpoint)
	assert.Equal(t, "https://example.com/token", config.TokenEndpoint)
	assert.Equal(t, []string{"scope1", "scope2"}, config.Scopes)
	assert.Equal(t, "audience", config.Audience)
	assert.NotNil(t, config.StorageProvider)
	assert.Equal(t, "https://example.com", metadata.Issuer)
	assert.Equal(t, "https://example.com/auth", metadata.AuthorizationEndpoint)
	assert.Equal(t, "https://example.com/token", metadata.TokenEndpoint)
	assert.Equal(t, "https://example.com/device", metadata.DeviceAuthorizationEndpoint)
	assert.Equal(t, "https://example.com/jwks", metadata.JwksURI)
}
