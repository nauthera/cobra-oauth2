package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type AuthorizationServerMetadataResponse struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
}

func FetchConfigFromDiscoveryURL(discoveryURL url.URL) (*AuthorizationServerMetadataResponse, error) {
	response, err := http.Get(discoveryURL.String())
	if err != nil {
		return nil, err
	}

	var metadata AuthorizationServerMetadataResponse
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}
