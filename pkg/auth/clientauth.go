package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ClientAuthMethod is a token_endpoint_auth_method value (RFC 8414 § 2,
// OIDC Core § 9).
type ClientAuthMethod string

// Client authentication methods implemented by this package. Others, such
// as tls_client_auth, plug in through [WithClientAuthenticator].
const (
	// ClientAuthAuto picks a method from the configuration and discovery.
	ClientAuthAuto ClientAuthMethod = ""
	// ClientAuthNone is a public client: client_id in the body, no secret.
	ClientAuthNone ClientAuthMethod = "none"
	// ClientAuthSecretBasic sends the credentials in an HTTP Basic
	// Authorization header (RFC 6749 § 2.3.1, the method servers MUST
	// support).
	ClientAuthSecretBasic ClientAuthMethod = "client_secret_basic"
	// ClientAuthSecretPost sends client_id and client_secret in the
	// request body.
	ClientAuthSecretPost ClientAuthMethod = "client_secret_post"
	// ClientAuthPrivateKeyJWT sends a JWT signed with the client's private
	// key (RFC 7523 § 2.2). Selected by [WithPrivateKeyJWT].
	ClientAuthPrivateKeyJWT ClientAuthMethod = "private_key_jwt"
	// ClientAuthSecretJWT sends a JWT signed with HMAC keyed by the client
	// secret (OIDC Core § 9). The secret never leaves the client, but the
	// server must hold it in the clear; prefer private_key_jwt.
	ClientAuthSecretJWT ClientAuthMethod = "client_secret_jwt"
)

// AssertionAudience selects the aud claim of a client assertion.
type AssertionAudience string

// Client assertion audiences.
const (
	// AssertionAudienceIssuer uses the issuer identifier, as RFC 7523bis
	// and the OAuth 2.0 Security BCP recommend. The default.
	AssertionAudienceIssuer AssertionAudience = ""
	// AssertionAudienceTokenEndpoint uses the token endpoint URL, as OIDC
	// Core § 9 describes and some providers (Okta, Entra ID) expect.
	AssertionAudienceTokenEndpoint AssertionAudience = "token_endpoint"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// assertionLifetime is the exp - iat of client assertions: short, as
	// RFC 7523 § 3 asks, yet enough for moderate clock skew.
	assertionLifetime = 2 * time.Minute
)

// ClientAuthenticator adds client authentication to a back-channel request.
// It is called for every attempt, so it can mint a fresh assertion each
// time.
type ClientAuthenticator interface {
	// Method returns the token_endpoint_auth_method this authenticator
	// implements, for example "private_key_jwt".
	Method() ClientAuthMethod
	// Authenticate modifies req to carry the client's credentials.
	Authenticate(ctx context.Context, req *EndpointRequest) error
}

type builtinAuth struct {
	method             ClientAuthMethod
	clientID, secret   string
	deviceClientIDOnly bool
}

// Method implements ClientAuthenticator.
func (a *builtinAuth) Method() ClientAuthMethod { return a.method }

// Authenticate implements ClientAuthenticator.
func (a *builtinAuth) Authenticate(_ context.Context, req *EndpointRequest) error {
	// Never send credentials twice, whatever an earlier layer added.
	req.Form.Del("client_secret")
	req.Header.Del("Authorization")

	method := a.method
	if req.Kind == EndpointDeviceAuthorization && a.deviceClientIDOnly {
		method = ClientAuthNone
	}
	switch method {
	case ClientAuthSecretBasic:
		// A pushed authorization request keeps client_id: it is one of the
		// authorization request's own parameters (RFC 9126 § 2.1).
		if req.Kind != EndpointPushedAuthorization {
			req.Form.Del("client_id")
		}
		req.Header.Set("Authorization", "Basic "+basicCredentials(a.clientID, a.secret))
	case ClientAuthSecretPost:
		req.Form.Set("client_id", a.clientID)
		req.Form.Set("client_secret", a.secret)
	default:
		req.Form.Set("client_id", a.clientID)
	}
	return nil
}

// basicCredentials encodes the client credentials for HTTP Basic as
// RFC 6749 § 2.3.1 requires: each part form-urlencoded first, so a colon or
// non-ASCII character in either survives. url.QueryEscape encodes a space
// as "+", which is valid form encoding; it is rewritten to %20 because some
// servers decode the parts as plain percent-encoding.
func basicCredentials(id, secret string) string {
	enc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	return base64.StdEncoding.EncodeToString([]byte(enc(id) + ":" + enc(secret)))
}

// clientAuthenticator returns the authenticator for this client, choosing a
// built-in method from the configuration and, for ClientAuthAuto, from the
// discovered token_endpoint_auth_methods_supported.
func (c *Client) clientAuthenticator(ctx context.Context) (ClientAuthenticator, error) {
	if c.cfg.authenticator != nil {
		return c.cfg.authenticator, nil
	}
	method := c.cfg.authMethod
	if method == ClientAuthAuto && c.cfg.assertionKey != nil {
		method = ClientAuthPrivateKeyJWT
	}
	if method == ClientAuthPrivateKeyJWT || method == ClientAuthSecretJWT {
		return c.jwtAuthenticator(ctx, method)
	}
	if method == ClientAuthAuto {
		method = ClientAuthNone
		if c.cfg.clientSecret != "" {
			method = ClientAuthSecretBasic
			if c.cfg.secretInBody {
				method = ClientAuthSecretPost
			}
			// Discovery is cached by now for any request that needed an
			// endpoint from it; with discovery off this costs nothing.
			if md, err := c.Metadata(ctx); err == nil {
				supported := md.TokenEndpointAuthMethodsSupported
				if len(supported) > 0 && !slices.Contains(supported, string(ClientAuthSecretBasic)) &&
					slices.Contains(supported, string(ClientAuthSecretPost)) {
					method = ClientAuthSecretPost
				}
			}
		}
	}
	return &builtinAuth{
		method:             method,
		clientID:           c.cfg.clientID,
		secret:             c.cfg.clientSecret,
		deviceClientIDOnly: c.cfg.deviceClientIDOnly,
	}, nil
}

// jwtAuth implements private_key_jwt and client_secret_jwt: a JWT with
// iss = sub = client_id, the configured audience, a unique jti and a short
// lifetime, minted afresh for every request (RFC 7523 § 3).
type jwtAuth struct {
	method   ClientAuthMethod
	clientID string
	key      any // crypto.Signer for private_key_jwt, []byte for client_secret_jwt
	keyID    string
	alg      jose.SignatureAlgorithm
	audience string
	now      func() time.Time
}

// Method implements ClientAuthenticator.
func (a *jwtAuth) Method() ClientAuthMethod { return a.method }

// Authenticate implements ClientAuthenticator.
func (a *jwtAuth) Authenticate(_ context.Context, req *EndpointRequest) error {
	req.Form.Del("client_secret")
	req.Header.Del("Authorization")
	jti, err := randomToken(24)
	if err != nil {
		return err
	}
	now := a.now()
	payload, err := json.Marshal(map[string]any{
		"iss": a.clientID, "sub": a.clientID, "aud": a.audience, "jti": jti,
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return fmt.Errorf("client assertion claims: %w", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if a.keyID != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), a.keyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: a.alg, Key: a.key}, opts)
	if err != nil {
		return fmt.Errorf("client assertion signer: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign client assertion: %w", err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		return fmt.Errorf("serialize client assertion: %w", err)
	}
	req.Form.Set("client_id", a.clientID)
	req.Form.Set("client_assertion_type", clientAssertionType)
	req.Form.Set("client_assertion", raw)
	return nil
}

// jwtAuthenticator builds the authenticator for private_key_jwt or
// client_secret_jwt, choosing the algorithm against the server's
// token_endpoint_auth_signing_alg_values_supported.
func (c *Client) jwtAuthenticator(ctx context.Context, method ClientAuthMethod) (ClientAuthenticator, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	advertised := md.TokenEndpointAuthSigningAlgValuesSupported
	a := &jwtAuth{method: method, clientID: c.cfg.clientID, keyID: c.cfg.assertionKeyID, now: c.now}
	if method == ClientAuthSecretJWT {
		a.key = []byte(c.cfg.clientSecret)
		a.alg = jose.HS256
		for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
			if len(advertised) == 0 || slices.Contains(advertised, string(alg)) {
				a.alg = alg
				break
			}
		}
	} else {
		a.key = c.cfg.assertionKey
		if a.alg, err = assertionAlg(c.cfg.assertionKey, advertised); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	if len(advertised) > 0 && !slices.Contains(advertised, string(a.alg)) {
		return nil, configErr("the server does not accept %s client assertions (it lists %s)",
			a.alg, sanitize(strings.Join(advertised, " "), maxDescriptionLen))
	}
	switch c.cfg.assertionAud {
	case AssertionAudienceTokenEndpoint:
		a.audience = md.TokenEndpoint
	default:
		a.audience = md.Issuer
	}
	return a, nil
}

// assertionAlg returns the JWS algorithm for a private key: ES256/384/512
// by curve, EdDSA for Ed25519, and RS256 for RSA unless the server lists
// only PS256.
func assertionAlg(key crypto.Signer, advertised []string) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", errors.New("private_key_jwt: unsupported ECDSA curve")
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return "", errors.New("private_key_jwt: RSA keys must have at least 2048 bits")
		}
		if len(advertised) > 0 && !slices.Contains(advertised, string(jose.RS256)) &&
			slices.Contains(advertised, string(jose.PS256)) {
			return jose.PS256, nil
		}
		return jose.RS256, nil
	case nil:
		return "", errors.New("private_key_jwt: no signing key")
	default:
		return "", fmt.Errorf("private_key_jwt: unsupported key type %T (use an ECDSA, Ed25519 or RSA private key, "+
			"or WithClientAuthenticator for keys held elsewhere)", key)
	}
}
