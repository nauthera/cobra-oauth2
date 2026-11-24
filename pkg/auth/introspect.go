package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Introspection is an RFC 7662 § 2.2 introspection response.
type Introspection struct {
	// Active reports whether the token is currently valid at the server.
	// Every other member is meaningful only when it is true.
	Active    bool
	Scope     string
	ClientID  string
	Username  string
	TokenType string
	Expiry    time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Subject   string
	Audience  []string
	Issuer    string
	JWTID     string
	// Raw holds every member of the response, including the ones above.
	Raw map[string]any
}

// Introspect asks the authorization server about token (RFC 7662). It is
// for confidential clients, such as a CLI that runs as a service with
// [FlowClientCredentials]: servers refuse introspection from public
// clients, so it fails with [ErrInvalidConfig] without sending anything
// when the client has no credentials. A token the server does not know, or
// that expired or was revoked, is not an error: the result is
// Active == false.
func (c *Client) Introspect(ctx context.Context, token string) (*Introspection, error) {
	if token == "" {
		return nil, configErr("introspect: no token")
	}
	if !c.cfg.confidential() {
		return nil, configErr("introspection needs a confidential client (a secret, WithPrivateKeyJWT or a client authenticator)")
	}
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if md.IntrospectionEndpoint == "" {
		return nil, ErrIntrospectionUnsupported
	}
	resp, err := c.postForm(ctx, EndpointIntrospection, md.IntrospectionEndpoint, url.Values{"token": {token}})
	if err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	fields, err := checkResponse("introspection", resp)
	if err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	if fields == nil {
		return nil, fmt.Errorf("%w: introspection response is not JSON", ErrInvalidResponse)
	}
	return parseIntrospection(fields)
}

func parseIntrospection(fields map[string]any) (*Introspection, error) {
	in := &Introspection{Raw: fields}
	switch v := fields["active"].(type) {
	case bool:
		in.Active = v
	case string:
		in.Active = v == "true"
	case nil:
		return nil, fmt.Errorf("%w: introspection response has no active member", ErrInvalidResponse)
	default:
		return nil, fmt.Errorf("%w: introspection active member is not a boolean", ErrInvalidResponse)
	}
	if !in.Active {
		return in, nil
	}
	in.Scope = normalizeScope(stringField(fields, "scope"))
	in.ClientID = stringField(fields, "client_id")
	in.Username = stringField(fields, "username")
	in.TokenType = stringField(fields, "token_type")
	in.Subject = stringField(fields, "sub")
	in.Issuer = stringField(fields, "iss")
	in.JWTID = stringField(fields, "jti")
	in.Expiry = unixField(fields, "exp")
	in.IssuedAt = unixField(fields, "iat")
	in.NotBefore = unixField(fields, "nbf")
	switch v := fields["aud"].(type) {
	case string:
		in.Audience = []string{v}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				in.Audience = append(in.Audience, s)
			}
		}
	}
	return in, nil
}

// unixField returns a NumericDate member as a time, zero when absent.
func unixField(fields map[string]any, name string) time.Time {
	if n, ok := numberField(fields, name); ok {
		return time.Unix(n, 0)
	}
	if n, ok := fields[name].(json.Number); ok {
		// Beyond numberField's int32 bound: still a valid NumericDate.
		if i, err := n.Int64(); err == nil && i > 0 {
			return time.Unix(i, 0)
		}
	}
	return time.Time{}
}
