package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	wellKnownOIDC  = "/.well-known/openid-configuration"
	wellKnownOAuth = "/.well-known/oauth-authorization-server"
)

// errDocumentRefused marks a metadata document that was served but refused
// (wrong issuer, bad endpoints, not JSON). It ends the search: a document
// in the right place with the wrong content is a misconfiguration or a
// mix-up attack, not a sign that the real one is elsewhere.
var errDocumentRefused = errors.New("discovery document refused")

// Metadata is the subset of authorization server metadata (RFC 8414,
// OpenID Connect Discovery 1.0) this package uses. Unknown members are
// ignored.
type Metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string   `json:"token_endpoint,omitempty"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                    string   `json:"jwks_uri,omitempty"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`
	DPoPSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
}

// grantAliases are spellings other than the registered URN that servers
// publish in grant_types_supported: GitLab (Doorkeeper) lists the device
// grant as "device_code".
var grantAliases = map[GrantType][]string{
	GrantDeviceCode: {"device_code"},
}

// SupportsGrant reports whether the server advertises the grant type. A
// server that does not publish grant_types_supported is assumed to support
// it; the token endpoint will say otherwise.
func (m *Metadata) SupportsGrant(g GrantType) bool {
	if len(m.GrantTypesSupported) == 0 || slices.Contains(m.GrantTypesSupported, string(g)) {
		return true
	}
	for _, alias := range grantAliases[g] {
		if slices.Contains(m.GrantTypesSupported, alias) {
			return true
		}
	}
	return false
}

// MetadataURLs returns the locations where the metadata of issuer may be
// published, in the order they are tried: the OpenID Connect location
// (issuer + /.well-known/openid-configuration), then the RFC 8414 § 3.1
// location with the well-known segment inserted before the issuer's path.
// For an issuer without a path, RFC 8414's location is the root one.
func MetadataURLs(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("issuer must not have a query or fragment")
	}
	oidc := strings.TrimSuffix(issuer, "/") + wellKnownOIDC
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	origin := u.Scheme + "://" + u.Host
	rfc := origin + wellKnownOAuth + path
	if rfc == oidc {
		return []string{oidc}, nil
	}
	return []string{oidc, rfc}, nil
}

// issuerFromDiscoveryURL derives the issuer a metadata URL belongs to, for
// either the appended (OIDC) or the inserted (RFC 8414) form.
func issuerFromDiscoveryURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse discovery URL: %w", err)
	}
	origin := u.Scheme + "://" + u.Host
	p := u.EscapedPath()
	for _, wk := range []string{wellKnownOIDC, wellKnownOAuth} {
		if rest, ok := strings.CutPrefix(p, wk); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			return origin + rest, nil
		}
		if base, ok := strings.CutSuffix(p, wk); ok {
			return origin + base, nil
		}
	}
	return "", fmt.Errorf("discovery URL %s has no well-known suffix; set the issuer with WithIssuer too", u.Redacted())
}

// fetchMetadata retrieves and validates the metadata document at one URL.
func (c *Client) fetchMetadata(ctx context.Context, docURL, issuer string) (*Metadata, error) {
	status, body, header, err := c.getJSON(ctx, "discovery", docURL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &StatusError{StatusCode: status, Endpoint: "discovery"}
	}
	if ct := header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
			return nil, fmt.Errorf("%w: %w: content type %q", errDocumentRefused, ErrInvalidResponse, sanitize(ct, 64))
		}
	}
	var md Metadata
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", errDocumentRefused, ErrInvalidResponse, err)
	}
	if !c.issuerMatches(issuer, md.Issuer) && !c.entraResolvedIssuer(issuer, md.Issuer) {
		return nil, fmt.Errorf("%w: %w: the document names issuer %q, want %q",
			errDocumentRefused, ErrIssuerMismatch, sanitize(md.Issuer, maxURILen), issuer)
	}
	if err := c.validateMetadataEndpoints(&md); err != nil {
		return nil, fmt.Errorf("%w: %w", errDocumentRefused, err)
	}
	return &md, nil
}

// issuerMatches is the RFC 8414 § 3.3 check: an exact string comparison,
// with one narrow, opt-in exception for Microsoft Entra ID's multi-tenant
// metadata, which names "{tenantid}" in place of the tenant.
func (c *Client) issuerMatches(want, got string) bool {
	if got == want {
		return true
	}
	if c.cfg.tenantIssuer && strings.Contains(got, "{tenantid}") {
		prefix, suffix, _ := strings.Cut(got, "{tenantid}")
		// The length check keeps prefix and suffix from overlapping inside
		// want, which would make the slice below invalid.
		if len(want) <= len(prefix)+len(suffix) || !strings.HasPrefix(want, prefix) || !strings.HasSuffix(want, suffix) {
			return false
		}
		return !strings.Contains(want[len(prefix):len(want)-len(suffix)], "/")
	}
	return false
}

// entraResolvedIssuer accepts the metadata of an Entra ID tenant that was
// configured by a name rather than its ID: for a verified domain
// (contoso.onmicrosoft.com) or "consumers", Entra's document names the
// issuer with the tenant's GUID in place of the name. Only that one path
// segment may differ, and only to a GUID; scheme, host and the rest of the
// path must be identical. The document's issuer then becomes the one the
// RFC 9207 iss parameter and ID tokens are compared with. It applies to
// discovery only, never to an authorization response.
func (c *Client) entraResolvedIssuer(configured, doc string) bool {
	if !c.cfg.tenantIssuer {
		return false
	}
	cu, err := url.Parse(configured)
	if err != nil {
		return false
	}
	du, err := url.Parse(doc)
	if err != nil || cu.Scheme != du.Scheme || cu.Host != du.Host || cu.RawQuery != "" || du.RawQuery != "" {
		return false
	}
	cs, ds := strings.Split(cu.EscapedPath(), "/"), strings.Split(du.EscapedPath(), "/")
	// "/<tenant>/v2.0" splits into "", tenant, "v2.0".
	if len(cs) < 2 || len(cs) != len(ds) || cs[0] != "" || ds[0] != "" {
		return false
	}
	if cs[1] == ds[1] || isGUID(cs[1]) || !isGUID(ds[1]) {
		return false
	}
	return slices.Equal(cs[2:], ds[2:])
}

// isGUID reports whether s has the 8-4-4-4-12 hex form of a GUID.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", rune(s[i])) {
				return false
			}
		}
	}
	return true
}

// validateMetadataEndpoints refuses a document whose endpoints are not
// https: discovery must not downgrade the transport of credentials.
func (c *Client) validateMetadataEndpoints(md *Metadata) error {
	for name, ep := range map[string]string{
		"authorization":        md.AuthorizationEndpoint,
		"token":                md.TokenEndpoint,
		"device_authorization": md.DeviceAuthorizationEndpoint,
		"revocation":           md.RevocationEndpoint,
		"introspection":        md.IntrospectionEndpoint,
		"userinfo":             md.UserinfoEndpoint,
		"jwks":                 md.JWKSURI,
		"end_session":          md.EndSessionEndpoint,
		"pushed_authorization": md.PushedAuthorizationRequestEndpoint,
	} {
		if ep == "" {
			continue
		}
		if _, err := validateEndpoint(name, ep, c.cfg.insecureHTTP); err != nil {
			return fmt.Errorf("discovery document: %w", err)
		}
	}
	return nil
}

// discover fetches the metadata, trying each candidate location in order.
// A document that names the wrong issuer stops the search: it is a sign of
// misconfiguration or a mix-up attack, not of a document in another place.
func (c *Client) discover(ctx context.Context) (*Metadata, error) {
	issuer := c.cfg.issuer
	var candidates []string
	if c.cfg.discoveryURL != "" {
		if issuer == "" {
			derived, err := issuerFromDiscoveryURL(c.cfg.discoveryURL)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
			}
			issuer = derived
		}
		candidates = []string{c.cfg.discoveryURL}
	} else {
		urls, err := MetadataURLs(issuer)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
		}
		candidates = urls
	}

	var errs []error
	for _, u := range candidates {
		md, err := c.fetchMetadata(ctx, u, issuer)
		if err == nil {
			c.logger().DebugContext(ctx, "discovered authorization server metadata", "url", u)
			return md, nil
		}
		if ctx.Err() != nil || errors.Is(err, errDocumentRefused) {
			return nil, fmt.Errorf("%w: %s: %w", ErrDiscovery, u, err)
		}
		errs = append(errs, fmt.Errorf("%s: %w", u, err))
	}
	return nil, fmt.Errorf("%w: %w", ErrDiscovery, errors.Join(errs...))
}

// Metadata returns the authorization server metadata: the discovered
// document (fetched once and cached for the life of the Client) with the
// explicitly configured endpoints layered on top and provider defaults
// filling gaps. With discovery disabled it is built from configuration
// alone.
func (c *Client) Metadata(ctx context.Context) (*Metadata, error) {
	c.mdMu.Lock()
	defer c.mdMu.Unlock()
	if c.md != nil {
		cp := *c.md
		return &cp, nil
	}

	md := &Metadata{Issuer: c.cfg.issuer}
	if c.discoveryEnabled() {
		d, err := c.discover(ctx)
		if err != nil {
			return nil, err
		}
		md = d
	}
	apply := func(dst *string, override, fallback string) {
		if override != "" {
			*dst = override
		} else if *dst == "" {
			*dst = fallback
		}
	}
	o, f := c.cfg.overrides, c.cfg.fallbacks
	apply(&md.AuthorizationEndpoint, o.Authorization, f.Authorization)
	apply(&md.TokenEndpoint, o.Token, f.Token)
	apply(&md.DeviceAuthorizationEndpoint, o.DeviceAuthorization, f.DeviceAuthorization)
	apply(&md.RevocationEndpoint, o.Revocation, f.Revocation)
	apply(&md.IntrospectionEndpoint, o.Introspection, f.Introspection)
	apply(&md.UserinfoEndpoint, o.UserInfo, f.UserInfo)
	apply(&md.JWKSURI, o.JWKS, f.JWKS)
	apply(&md.EndSessionEndpoint, o.EndSession, f.EndSession)
	apply(&md.PushedAuthorizationRequestEndpoint, o.PushedAuthorization, f.PushedAuthorization)
	if md.Issuer == "" {
		md.Issuer = c.storageIssuer()
	}
	if err := c.validateMetadataEndpoints(md); err != nil {
		return nil, err
	}
	if md.TokenEndpoint == "" {
		return nil, configErr("no token endpoint: the provider's metadata has none and none was configured")
	}
	c.md = md
	cp := *md
	return &cp, nil
}

func (c *Client) discoveryEnabled() bool {
	return !c.cfg.noDiscovery && (c.cfg.issuer != "" || c.cfg.discoveryURL != "")
}
