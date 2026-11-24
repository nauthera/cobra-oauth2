package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// TokenTypeIdentifier is an RFC 8693 § 3 token type URI, naming the kind
// of a token passed to or returned from a token exchange.
type TokenTypeIdentifier string

// Token type identifiers registered by RFC 8693 § 3.
//
//nolint:gosec // G101: token type URNs, not credentials
const (
	AccessTokenType  TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token"
	RefreshTokenType TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:refresh_token"
	IDTokenType      TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:id_token"
	JWTTokenType     TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:jwt"
	SAML1TokenType   TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:saml1"
	SAML2TokenType   TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:saml2"
)

// ExchangeRequest is an RFC 8693 token exchange request.
type ExchangeRequest struct {
	// SubjectToken is the token that represents the party on whose behalf
	// the new token is requested. When empty, the client's own access
	// token is used (refreshed first if needed) with SubjectTokenType
	// defaulting to AccessTokenType.
	SubjectToken string
	// SubjectTokenType is the type of SubjectToken. Required when
	// SubjectToken is set.
	SubjectTokenType TokenTypeIdentifier
	// ActorToken optionally represents the acting party (delegation).
	ActorToken string
	// ActorTokenType is the type of ActorToken; required with it.
	ActorTokenType TokenTypeIdentifier
	// RequestedTokenType is the type of token wanted; the server decides
	// when it is empty.
	RequestedTokenType TokenTypeIdentifier
	// Audience names the logical services the token is for.
	Audience []string
	// Resource names the APIs the token is for, as absolute URIs
	// (RFC 8707).
	Resource []string
	// Scope is the scope requested for the new token.
	Scope []string
}

// ExchangeResult is the response to a token exchange.
type ExchangeResult struct {
	// Token is the issued token. Its AccessToken holds the issued token
	// whatever its type; TokenType is Bearer, DPoP or [TokenTypeNA] for a
	// token that is not an access token. It is not stored.
	Token *storage.Token
	// IssuedTokenType is the type of the issued token.
	IssuedTokenType TokenTypeIdentifier
}

// ExchangeToken runs the RFC 8693 token exchange grant, for example to
// trade the CLI's token for one scoped to another API, or to act on behalf
// of another subject. The provider must advertise the grant in
// grant_types_supported when it publishes that list; otherwise the call
// fails with [ErrUnsupportedFlow] before any request is sent. With DPoP in
// use, an exchange for an access token is bound to a new key. The result is
// not stored.
func (c *Client) ExchangeToken(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if !md.SupportsGrant(GrantTokenExchange) {
		return nil, fmt.Errorf("%w: the provider does not list token exchange in grant_types_supported", ErrUnsupportedFlow)
	}
	if req.SubjectToken == "" {
		if req.SubjectTokenType != "" && req.SubjectTokenType != AccessTokenType {
			return nil, configErr("token exchange: subject token type %s needs a subject token", req.SubjectTokenType)
		}
		at, err := c.AccessToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("token exchange: subject token: %w", err)
		}
		req.SubjectToken, req.SubjectTokenType = at, AccessTokenType
	}
	if req.SubjectTokenType == "" {
		return nil, configErr("token exchange: subject token type is required")
	}
	if (req.ActorToken == "") != (req.ActorTokenType == "") {
		return nil, configErr("token exchange: actor token and actor token type go together")
	}
	for _, r := range req.Resource {
		if err := validateResource(r); err != nil {
			return nil, fmt.Errorf("%w: token exchange: %w", ErrInvalidConfig, err)
		}
	}

	form := url.Values{
		"grant_type":         {string(GrantTokenExchange)},
		"subject_token":      {req.SubjectToken},
		"subject_token_type": {string(req.SubjectTokenType)},
	}
	if req.ActorToken != "" {
		form.Set("actor_token", req.ActorToken)
		form.Set("actor_token_type", string(req.ActorTokenType))
	}
	if req.RequestedTokenType != "" {
		form.Set("requested_token_type", string(req.RequestedTokenType))
	}
	if len(req.Audience) > 0 {
		form["audience"] = append([]string(nil), req.Audience...)
	}
	if len(req.Resource) > 0 {
		form["resource"] = append([]string(nil), req.Resource...)
	}
	scope := strings.Join(req.Scope, " ")
	if scope != "" {
		form.Set("scope", scope)
	}
	addParams(form, c.cfg.tokenParams)

	var key *dpopKey
	if req.RequestedTokenType == "" || req.RequestedTokenType == AccessTokenType {
		if key, err = c.loginDPoPKey(ctx, md); err != nil {
			return nil, err
		}
	}
	resp, err := c.postFormDPoP(ctx, EndpointToken, md.TokenEndpoint, form, key)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	fields, err := checkResponse("token", resp)
	if err != nil {
		if errors.Is(err, ErrTemporarilyUnavailable) && len(md.GrantTypesSupported) == 0 {
			// nauthera-server and others answer an exchange they do not
			// implement with 503 temporarily_unavailable.
			return nil, fmt.Errorf("%w: token exchange: %w", ErrUnsupportedFlow, err)
		}
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	issued := stringField(fields, "issued_token_type")
	if issued == "" {
		return nil, fmt.Errorf("%w: token exchange response has no issued_token_type", ErrInvalidResponse)
	}
	tok, err := tokenFromFields(fields, c.now(), scope, true)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if key != nil && tok.TokenType != TokenTypeNA {
		if err := c.bindDPoP(ctx, tok, key, true); err != nil {
			return nil, err
		}
	}
	key2 := c.StorageKey()
	tok.Version, tok.Issuer, tok.ClientID = storage.CurrentVersion, key2.Issuer, key2.ClientID
	return &ExchangeResult{Token: tok, IssuedTokenType: TokenTypeIdentifier(sanitize(issued, maxURILen))}, nil
}
