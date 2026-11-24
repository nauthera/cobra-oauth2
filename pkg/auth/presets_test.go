package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPresetsBuildValidClients(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		opt    Option
		issuer string
	}{
		"nauthera": {Nauthera("https://auth.example.com/orgs/acme"), "https://auth.example.com/orgs/acme"},
		"github":   {GitHub(), "https://github.com"},
		"ghes":     {GitHubEnterprise("github.example.com"), "https://github.example.com"},
		"google":   {Google(), "https://accounts.google.com"},
		"entra":    {EntraID("organizations"), "https://login.microsoftonline.com/organizations/v2.0"},
		"okta":     {Okta("https://example.okta.com/oauth2/default"), "https://example.okta.com/oauth2/default"},
		"auth0":    {Auth0("example.eu.auth0.com", "https://api.example.com"), "https://example.eu.auth0.com/"},
		"keycloak": {Keycloak("https://sso.example.com", "main"), "https://sso.example.com/realms/main"},
		"gitlab":   {GitLab("gitlab.com"), "https://gitlab.com"},
		"zitadel":  {Zitadel("https://example.zitadel.cloud"), "https://example.zitadel.cloud"},
		"cognito":  {Cognito("eu-west-1", "eu-west-1_abc", "example.auth.eu-west-1.amazoncognito.com"), "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc"},
		"dex":      {Dex("https://dex.example.com"), "https://dex.example.com"},
	}
	for name, tc := range cases {
		c, err := NewClient(tc.opt, WithClientID("c"), WithRedirectPort(8400))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c.Issuer() != tc.issuer {
			t.Errorf("%s: issuer %q, want %q", name, c.Issuer(), tc.issuer)
		}
	}
}

func TestGitHubPresetNeedsNoDiscovery(t *testing.T) {
	t.Parallel()
	c, err := NewClient(GitHub(), WithClientID("Iv1.abc"))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata without network: %v", err)
	}
	if md.DeviceAuthorizationEndpoint != "https://github.com/login/device/code" || md.TokenEndpoint != "https://github.com/login/oauth/access_token" {
		t.Fatalf("metadata: %+v", md)
	}
	if len(c.userScopes()) != 0 {
		t.Fatalf("GitHub preset requests default scopes %v", c.userScopes())
	}
	// Options after the preset win.
	c, err = NewClient(GitHub(), WithClientID("Iv1.abc"), WithScopes("repo"), WithTokenEndpoint("https://proxy.example/token"))
	if err != nil {
		t.Fatal(err)
	}
	md, _ = c.Metadata(context.Background())
	if md.TokenEndpoint != "https://proxy.example/token" || c.userScopes()[0] != "repo" {
		t.Fatalf("overrides ignored: %+v %v", md, c.userScopes())
	}
}

func TestPresetInputErrors(t *testing.T) {
	t.Parallel()
	for name, opt := range map[string]Option{
		"entra":    EntraID("a/b"),
		"keycloak": Keycloak("https://sso.example.com", ""),
		"cognito":  Cognito("", "pool", "d"),
		"ghes":     GitHubEnterprise(""),
		"auth0":    Auth0("", ""),
	} {
		if _, err := NewClient(opt, WithClientID("c")); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Cognito matches the callback URL exactly, port included: without a
// fixed port every browser login would fail at the provider.
func TestCognitoNeedsAFixedRedirectPort(t *testing.T) {
	t.Parallel()
	preset := Cognito("eu-west-1", "eu-west-1_abc", "example.auth.eu-west-1.amazoncognito.com")
	_, err := NewClient(preset, WithClientID("c"))
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "WithRedirectPort") {
		t.Fatalf("err = %v, want ErrInvalidConfig naming WithRedirectPort", err)
	}
	if _, err := NewClient(preset, WithClientID("c"), WithRedirectPort(8400)); err != nil {
		t.Fatalf("with a fixed port: %v", err)
	}
	// Machine-to-machine use needs no redirect at all.
	if _, err := NewClient(preset, WithClientID("c"), WithClientSecret("s"), WithFlow(FlowClientCredentials)); err != nil {
		t.Fatalf("client credentials: %v", err)
	}
}
