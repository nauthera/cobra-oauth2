package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// Provider presets.
//
// A preset is an [Option] that configures what is specific to one provider:
// its issuer or static endpoints, how it wants the client authenticated,
// default scopes that get a refresh token there, and the narrow issuer
// exceptions some providers need. Everything else stays standard. Put the
// preset first; options after it override what it set:
//
//	auth.NewAuthCommand(
//		auth.GitHub(),
//		auth.WithClientID("Iv1.0123456789abcdef"),
//		auth.WithScopes("repo"),
//	)
//
// Presets reflect each provider's documented behavior at the time of
// writing. Providers change; when one does, the options a preset sets can
// be overridden one by one.

func presetErr(format string, args ...any) Option {
	return func(c *config) {
		if c.optErr == nil {
			c.optErr = fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
		}
	}
}

func preset(name string, set func(c *config)) Option {
	return func(c *config) {
		c.providerName = name
		set(c)
	}
}

func presetScopes(c *config, scopes ...string) {
	c.presetScopes = scopes
	c.presetScopesSet = true
}

// httpsBase normalizes a host name or base URL to an https URL without a
// trailing slash.
func httpsBase(hostOrURL string) (string, error) {
	s := strings.TrimSpace(hostOrURL)
	if s == "" {
		return "", fmt.Errorf("empty host")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid host or URL %q", hostOrURL)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// Nauthera configures a nauthera-server issuer, for example
// "https://auth.example.com" or a tenant issuer
// "https://auth.example.com/orgs/acme". It requests openid and
// offline_access, which nauthera needs to issue a refresh token. nauthera
// supports DPoP (WithDPoP or WithDPoPAuto, which also binds the device and
// authorization code flows with dpop_jkt), PAR, resource indicators and
// private_key_jwt.
func Nauthera(issuer string) Option {
	return preset("nauthera", func(c *config) {
		c.issuer = issuer
		presetScopes(c, "openid", "offline_access")
	})
}

// GitHub configures github.com OAuth and GitHub Apps. GitHub has no
// discovery document, issues no ID tokens and no RFC 7009 revocation, and
// expects the client secret, where one is used, in the request body.
// The device flow must be enabled in the app's settings. Scopes are
// GitHub's own (repo, read:org); none are requested by default.
func GitHub() Option {
	return gitHub("https://github.com")
}

// GitHubEnterprise configures a GitHub Enterprise Server host, for example
// "github.example.com".
func GitHubEnterprise(host string) Option {
	base, err := httpsBase(host)
	if err != nil {
		return presetErr("GitHub Enterprise: %v", err)
	}
	return gitHub(base)
}

func gitHub(base string) Option {
	return preset("github", func(c *config) {
		c.issuer = base
		c.noDiscovery = true
		mergeEndpoints(&c.fallbacks, Endpoints{
			Authorization:       base + "/login/oauth/authorize",
			Token:               base + "/login/oauth/access_token",
			DeviceAuthorization: base + "/login/device/code",
		})
		c.secretInBody = true
		c.deviceClientIDOnly = true
		presetScopes(c)
	})
}

// Google configures Google accounts. Google's "Desktop app" and "TVs and
// limited input" clients come with a client secret that is not
// confidential but must be sent anyway; pass it with WithClientSecret. It
// goes in the request body, and only to the token endpoint. ID tokens may
// name either of Google's two issuer spellings.
func Google() Option {
	return preset("google", func(c *config) {
		c.issuer = "https://accounts.google.com"
		c.secretInBody = true
		c.deviceClientIDOnly = true
		c.issuerAliases = append(c.issuerAliases, "accounts.google.com")
		c.assertionAud = AssertionAudienceTokenEndpoint
		presetScopes(c, "openid", "email", "profile")
	})
}

// EntraID configures Microsoft Entra ID (v2.0 endpoints). tenant is a
// tenant ID, a verified domain, or "common", "organizations" or
// "consumers". For "common" and "organizations" the metadata names the
// issuer with a "{tenantid}" placeholder, which is accepted here and
// resolved from each ID token's tid claim. For "consumers" and a verified
// domain it names the tenant's GUID in place of the name, which is
// accepted too, and that issuer is then the one ID tokens must name. The app registration must allow public
// client flows for the device flow; do not configure a secret for a public
// client. offline_access is requested so Entra issues a refresh token.
func EntraID(tenant string) Option {
	if tenant == "" || strings.ContainsAny(tenant, "/?#") {
		return presetErr("Entra ID: invalid tenant %q", tenant)
	}
	return preset("entra", func(c *config) {
		c.issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
		c.tenantIssuer = true
		// Entra expects the token endpoint as a client assertion's aud.
		c.assertionAud = AssertionAudienceTokenEndpoint
		presetScopes(c, "openid", "profile", "offline_access")
	})
}

// Okta configures an Okta authorization server: the org server
// ("https://example.okta.com") or a custom one
// ("https://example.okta.com/oauth2/default"). Okta supports DPoP and
// always asks for a nonce, which the client handles; enable it with
// WithDPoP or WithDPoPAuto.
func Okta(issuer string) Option {
	return preset("okta", func(c *config) {
		c.issuer = issuer
		// Okta expects the token endpoint as a client assertion's aud.
		c.assertionAud = AssertionAudienceTokenEndpoint
		presetScopes(c, "openid", "profile", "offline_access")
	})
}

// Auth0 configures an Auth0 tenant or custom domain, for example
// "example.eu.auth0.com". audience names the API the access token is for;
// without it Auth0 issues an opaque token usable only at /userinfo. The
// issuer Auth0 publishes has a trailing slash, which this preset keeps.
func Auth0(domain, audience string) Option {
	base, err := httpsBase(domain)
	if err != nil {
		return presetErr("Auth0: %v", err)
	}
	return preset("auth0", func(c *config) {
		c.issuer = base + "/"
		if audience != "" {
			c.audience = audience
		}
		presetScopes(c, "openid", "profile", "offline_access")
	})
}

// Keycloak configures a Keycloak realm. baseURL is the server root, for
// example "https://sso.example.com" (append "/auth" for Keycloak before
// version 17). offline_access is not requested: in Keycloak it asks for an
// offline token with different session semantics, and a normal refresh
// token is issued without it.
func Keycloak(baseURL, realm string) Option {
	base, err := httpsBase(baseURL)
	if err != nil {
		return presetErr("Keycloak: %v", err)
	}
	if realm == "" || strings.ContainsAny(realm, "/?#") {
		return presetErr("Keycloak: invalid realm %q", realm)
	}
	return preset("keycloak", func(c *config) {
		c.issuer = base + "/realms/" + url.PathEscape(realm)
		presetScopes(c, "openid", "profile")
	})
}

// GitLab configures gitlab.com or a self-managed instance
// ("https://gitlab.example.com"). GitLab 17.1 and later support the device
// flow but may not advertise it in discovery, so its endpoint is filled in
// when missing. GitLab always issues refresh tokens and has no
// offline_access scope.
func GitLab(baseURL string) Option {
	base, err := httpsBase(baseURL)
	if err != nil {
		return presetErr("GitLab: %v", err)
	}
	return preset("gitlab", func(c *config) {
		c.issuer = base
		mergeEndpoints(&c.fallbacks, Endpoints{DeviceAuthorization: base + "/oauth/authorize_device"})
		presetScopes(c, "openid", "profile")
	})
}

// Zitadel configures a ZITADEL instance, for example
// "https://example.zitadel.cloud". Project audience scopes such as
// "urn:zitadel:iam:org:project:id:<id>:aud" can be added with WithScopes.
func Zitadel(issuer string) Option {
	return preset("zitadel", func(c *config) {
		c.issuer = issuer
		presetScopes(c, "openid", "profile", "offline_access")
	})
}

// Cognito configures an Amazon Cognito user pool. domain is the hosted UI
// domain ("example.auth.eu-west-1.amazoncognito.com" or a custom domain),
// used when the metadata lacks an endpoint. Cognito has no device flow,
// and matches callback URLs exactly, port included: register
// http://localhost:<port>/callback and set the same port with
// WithRedirectPort. Without a fixed port, [NewClient] returns an error
// wrapping [ErrInvalidConfig] for the browser flow.
func Cognito(region, userPoolID, domain string) Option {
	if region == "" || userPoolID == "" || strings.ContainsAny(region+userPoolID, "/?#") {
		return presetErr("Cognito: region and user pool ID are required")
	}
	base, err := httpsBase(domain)
	if err != nil {
		return presetErr("Cognito: %v", err)
	}
	return preset("cognito", func(c *config) {
		c.issuer = "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID
		mergeEndpoints(&c.fallbacks, Endpoints{
			Authorization: base + "/oauth2/authorize",
			Token:         base + "/oauth2/token",
			Revocation:    base + "/oauth2/revoke",
		})
		if c.redirectHost == defaultRedirectHost {
			c.redirectHost = "localhost"
		}
		if c.flow == FlowAuto {
			c.flow = FlowBrowser
		}
		c.exactRedirectPort = true
		presetScopes(c, "openid", "profile")
	})
}

// Dex configures a Dex issuer. Dex has no revocation endpoint, so logout
// only deletes the local tokens.
func Dex(issuer string) Option {
	return preset("dex", func(c *config) {
		c.issuer = issuer
		presetScopes(c, "openid", "profile", "offline_access")
	})
}
