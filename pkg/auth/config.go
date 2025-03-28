package auth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-playground/validator"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

type Option func(*Config)

// Config defines the configuration for OAuth2 device flow.
type Config struct {
	ClientId                    string   `json:"client_id" validate:"required"`
	ClientSecret                string   `json:"client_secret,omitempty"`
	DeviceAuthorizationEndpoint string   `json:"auth_url" validate:"required,url"`
	TokenEndpoint               string   `json:"token_url" validate:"required,url"`
	Scopes                      []string `json:"scopes" validate:"required,min=1,dive,required"`
	Audience                    string   `json:"audience,omitempty"`
	StorageProvider             storage.StorageProvider
	GrantType                   GrantType `json:"grant_type"`
}

func (c Config) IsValid() error {
	if c.StorageProvider == nil {
		return fmt.Errorf("storage provider is required")
	}

	validate := validator.New()
	if err := validate.Struct(c); err != nil {
		return err
	}
	return nil
}

func WithClientID(clientId string) Option {
	return func(c *Config) {
		c.ClientId = clientId
	}
}

func WithClientSecret(clientSecret string) Option {
	return func(c *Config) {
		c.ClientSecret = clientSecret
	}
}

func WithDeviceAuthorizationEndpoint(deviceAuthorizationEndpoint string) Option {
	return func(c *Config) {
		c.DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint
	}
}

func WithTokenEndpoint(tokenEndpoint string) Option {
	return func(c *Config) {
		c.TokenEndpoint = tokenEndpoint
	}
}

func WithScopes(scopes []string) Option {
	return func(c *Config) {
		c.Scopes = scopes
	}
}

func WithAudience(audience string) Option {
	return func(c *Config) {
		c.Audience = audience
	}
}

func WithDiscoveryURL(discoveryURL url.URL) Option {
	metadata, err := FetchConfigFromDiscoveryURL(discoveryURL)
	if err != nil {
		// this is a fatal error, so we panic
		panic(fmt.Errorf("failed to fetch OAuth2 metadata: %w", err))
	}

	// if device authorization endpoint is empty fallback to authorization url
	deviceAuthorizationEndpoint := metadata.DeviceAuthorizationEndpoint
	if deviceAuthorizationEndpoint == "" {
		deviceAuthorizationEndpoint = metadata.AuthorizationEndpoint
	}

	return func(c *Config) {
		c.DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint
		c.TokenEndpoint = metadata.TokenEndpoint
	}
}

func WithStorageProvider(storageProvider storage.StorageProvider) Option {
	return func(c *Config) {
		c.StorageProvider = storageProvider
	}
}

func WithGrantType(grantType GrantType) Option {
	return func(c *Config) {
		c.GrantType = grantType
	}
}

func configure(options ...Option) (*Config, error) {
	authConfig := &Config{
		Scopes:    strings.Split(DefaultScopes, " "),
		GrantType: DefaultGrantType,
	}

	for _, opt := range options {
		opt(authConfig)
	}

	if err := authConfig.IsValid(); err != nil {
		return nil, err
	}

	return authConfig, nil
}
