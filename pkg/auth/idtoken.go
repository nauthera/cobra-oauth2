package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// jwksRefetchInterval rate-limits refetching the JWKS for an unknown kid.
const jwksRefetchInterval = 5 * time.Minute

// idTokenAlgs is the library's allowlist of ID token signature algorithms:
// asymmetric only. none and the HMAC algorithms are never accepted.
var idTokenAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// IDTokenClaims are the validated claims of an OpenID Connect ID token.
type IDTokenClaims struct {
	Issuer            string
	Subject           string
	Audience          []string
	AuthorizedParty   string
	Expiry            time.Time
	IssuedAt          time.Time
	Nonce             string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	// Raw holds every claim, including the ones above.
	Raw map[string]any
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

type numericDate struct {
	t   time.Time
	set bool
}

func (d *numericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return errors.New("time claim is not a number")
	}
	d.t, d.set = time.Unix(int64(f), 0), true
	return nil
}

type rawClaims struct {
	Iss               string      `json:"iss"`
	Sub               string      `json:"sub"`
	Aud               audience    `json:"aud"`
	Azp               string      `json:"azp"`
	Exp               numericDate `json:"exp"`
	Iat               numericDate `json:"iat"`
	Nbf               numericDate `json:"nbf"`
	Nonce             string      `json:"nonce"`
	Tid               string      `json:"tid"`
	Email             string      `json:"email"`
	EmailVerified     any         `json:"email_verified"`
	Name              string      `json:"name"`
	PreferredUsername string      `json:"preferred_username"`
}

func (r *rawClaims) toClaims(all map[string]any) *IDTokenClaims {
	verified := false
	switch v := r.EmailVerified.(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true" // some providers send a string
	}
	return &IDTokenClaims{
		Issuer: r.Iss, Subject: r.Sub, Audience: r.Aud, AuthorizedParty: r.Azp,
		Expiry: r.Exp.t, IssuedAt: r.Iat.t, Nonce: r.Nonce,
		Email: r.Email, EmailVerified: verified, Name: r.Name, PreferredUsername: r.PreferredUsername,
		Raw: all,
	}
}

// decodeClaims parses a JWT payload into the typed and the raw claims.
func decodeClaims(payload []byte) (*rawClaims, map[string]any, error) {
	var rc rawClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return nil, nil, fmt.Errorf("%w: claims: %w", ErrInvalidIDToken, err)
	}
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, nil, fmt.Errorf("%w: claims: %w", ErrInvalidIDToken, err)
	}
	return &rc, all, nil
}

// unverifiedClaims decodes an ID token's claims without checking anything.
// Only for display of a token that was validated when it was stored.
func unverifiedClaims(raw string) (*IDTokenClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrInvalidIDToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrInvalidIDToken, err)
	}
	rc, all, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	return rc.toClaims(all), nil
}

// VerifyIDToken validates an ID token as OIDC Core § 3.1.3.7 requires: a
// JWS (not JWE) signed with an allowed asymmetric algorithm by a key from
// the provider's JWKS, issued by the configured issuer for this client,
// unexpired, and carrying nonce when one was sent (pass "" for the device
// flow and refreshes, which have none).
func (c *Client) VerifyIDToken(ctx context.Context, raw, nonce string) (*IDTokenClaims, error) {
	md, err := c.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if md.JWKSURI == "" {
		return nil, fmt.Errorf("%w: the provider publishes no jwks_uri to verify it with "+
			"(WithJWKSURL, or WithIDTokenValidation(false))", ErrInvalidIDToken)
	}
	algs := idTokenAlgs
	if len(md.IDTokenSigningAlgValuesSupported) > 0 {
		algs = slices.DeleteFunc(slices.Clone(idTokenAlgs), func(a jose.SignatureAlgorithm) bool {
			return !slices.Contains(md.IDTokenSigningAlgValuesSupported, string(a))
		})
		if len(algs) == 0 {
			return nil, fmt.Errorf("%w: the provider signs ID tokens only with algorithms this library refuses", ErrInvalidIDToken)
		}
	}
	jws, err := jose.ParseSignedCompact(raw, algs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: want exactly one signature", ErrInvalidIDToken)
	}
	payload, err := c.verifySignature(ctx, md, jws)
	if err != nil {
		return nil, err
	}
	rc, all, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := c.checkClaims(md, rc, nonce); err != nil {
		return nil, err
	}
	return rc.toClaims(all), nil
}

func (c *Client) checkClaims(md *Metadata, rc *rawClaims, nonce string) error {
	if !c.idTokenIssuerOK(md, rc) {
		return fmt.Errorf("%w: %w: iss %q", ErrInvalidIDToken, ErrIssuerMismatch, sanitize(rc.Iss, maxURILen))
	}
	if rc.Sub == "" {
		return fmt.Errorf("%w: no sub", ErrInvalidIDToken)
	}
	if !slices.Contains(rc.Aud, c.cfg.clientID) {
		return fmt.Errorf("%w: aud does not contain the client ID", ErrInvalidIDToken)
	}
	if len(rc.Aud) > 1 && rc.Azp == "" {
		return fmt.Errorf("%w: several audiences but no azp", ErrInvalidIDToken)
	}
	if rc.Azp != "" && rc.Azp != c.cfg.clientID {
		return fmt.Errorf("%w: azp is not the client ID", ErrInvalidIDToken)
	}
	now, leeway := c.now(), c.cfg.idTokenLeeway
	if !rc.Exp.set {
		return fmt.Errorf("%w: no exp", ErrInvalidIDToken)
	}
	if !now.Add(-leeway).Before(rc.Exp.t) {
		return fmt.Errorf("%w: expired at %s", ErrInvalidIDToken, rc.Exp.t.UTC().Format(time.RFC3339))
	}
	if rc.Iat.set && rc.Iat.t.After(now.Add(leeway)) {
		return fmt.Errorf("%w: issued in the future", ErrInvalidIDToken)
	}
	if rc.Nbf.set && rc.Nbf.t.After(now.Add(leeway)) {
		return fmt.Errorf("%w: not valid yet", ErrInvalidIDToken)
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(rc.Nonce), []byte(nonce)) != 1 {
		return fmt.Errorf("%w: nonce mismatch", ErrInvalidIDToken)
	}
	return nil
}

// idTokenIssuerOK compares iss with the metadata's issuer exactly, plus the
// preset's narrow exceptions: Google's legacy issuer without scheme, and
// Entra's {tenantid} template filled with the token's tid claim.
func (c *Client) idTokenIssuerOK(md *Metadata, rc *rawClaims) bool {
	if rc.Iss == md.Issuer || slices.Contains(c.cfg.issuerAliases, rc.Iss) {
		return true
	}
	if c.cfg.tenantIssuer && strings.Contains(md.Issuer, "{tenantid}") && rc.Tid != "" && !strings.ContainsAny(rc.Tid, "/?#") {
		return rc.Iss == strings.ReplaceAll(md.Issuer, "{tenantid}", rc.Tid)
	}
	return false
}

type jwksCache struct {
	keys    []jose.JSONWebKey
	fetched time.Time
}

// verifySignature finds the signing key in the JWKS by kid, refetching the
// set once (rate-limited) when the kid is unknown, to follow key rotation.
func (c *Client) verifySignature(ctx context.Context, md *Metadata, jws *jose.JSONWebSignature) ([]byte, error) {
	hdr := jws.Signatures[0].Header
	for attempt := 0; attempt < 2; attempt++ {
		keys, fresh, err := c.jwksKeys(ctx, md.JWKSURI, attempt > 0)
		if err != nil {
			return nil, err
		}
		candidates := matchingKeys(keys, hdr.KeyID, hdr.Algorithm)
		for _, k := range candidates {
			if payload, err := jws.Verify(k.Key); err == nil {
				return payload, nil
			}
		}
		if len(candidates) > 0 || fresh {
			break
		}
	}
	return nil, fmt.Errorf("%w: signature does not verify with any key in the provider's JWKS", ErrInvalidIDToken)
}

func matchingKeys(keys []jose.JSONWebKey, kid, alg string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, k := range keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != alg {
			continue
		}
		if !k.IsPublic() {
			continue
		}
		out = append(out, k)
	}
	return out
}

// jwksKeys returns the cached key set, fetching it when absent or when a
// refetch is requested and the cache is older than the rate limit. fresh
// reports whether the keys were fetched by this call.
func (c *Client) jwksKeys(ctx context.Context, jwksURL string, refetch bool) ([]jose.JSONWebKey, bool, error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()
	if c.jwks != nil && (!refetch || c.now().Sub(c.jwks.fetched) < jwksRefetchInterval) {
		return c.jwks.keys, false, nil
	}
	status, body, _, err := c.getJSON(ctx, "jwks", jwksURL)
	if err != nil {
		return nil, false, fmt.Errorf("fetch JWKS: %w", err)
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("fetch JWKS: %w", &StatusError{StatusCode: status, Endpoint: "jwks"})
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false, fmt.Errorf("%w: JWKS: %w", ErrInvalidResponse, err)
	}
	keys := make([]jose.JSONWebKey, 0, len(doc.Keys))
	for _, raw := range doc.Keys {
		var k jose.JSONWebKey
		// Skip keys of types go-jose does not know (an encryption-only
		// X25519 key, say) instead of rejecting the whole set.
		if err := k.UnmarshalJSON(raw); err == nil {
			keys = append(keys, k)
		}
	}
	c.jwks = &jwksCache{keys: keys, fetched: c.now()}
	return keys, true, nil
}

// checkIDToken validates the ID token in tok, if there is one and
// validation is enabled. On a refresh, prev is the token set being
// replaced; the new ID token must then name the same issuer and subject
// (OIDC Core § 12.2).
func (c *Client) checkIDToken(ctx context.Context, tok, prev *storage.Token, nonce string) error {
	if tok.IDToken == "" || !c.cfg.verifyIDToken {
		return nil
	}
	claims, err := c.VerifyIDToken(ctx, tok.IDToken, nonce)
	if err != nil {
		return err
	}
	if prev != nil && prev.IDToken != "" {
		if old, err := unverifiedClaims(prev.IDToken); err == nil &&
			(old.Subject != claims.Subject || old.Issuer != claims.Issuer) {
			return fmt.Errorf("%w: the refreshed ID token names a different subject", ErrInvalidIDToken)
		}
	}
	return nil
}
