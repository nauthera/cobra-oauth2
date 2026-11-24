package oauthtest

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const signingKeyID = "oauthtest-1"

// errNoProof means a request carried no DPoP header.
var errNoProof = errors.New("no DPoP proof")

// serveJWKS publishes the ID token signing key.
func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: s.key.Public(), KeyID: signingKeyID, Algorithm: s.alg, Use: "sig",
	}}})
}

// SignJWT signs claims with the server's ID token key (Config.SigningAlg,
// kid in the header), for tests that hand-craft an ID token.
func (s *Server) SignJWT(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(s.alg), Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), signingKeyID))
	if err != nil {
		s.t.Errorf("oauthtest: signer: %v", err)
		return ""
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		s.t.Errorf("oauthtest: claims: %v", err)
		return ""
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		s.t.Errorf("oauthtest: sign: %v", err)
		return ""
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		s.t.Errorf("oauthtest: serialize: %v", err)
		return ""
	}
	return raw
}

// idToken issues an ID token for a grant.
func (s *Server) idToken(clientID, nonce string, now time.Time) string {
	iss := s.issuer
	if s.cfg.IDTokenIssuer != "" {
		iss, _ = s.expand(s.cfg.IDTokenIssuer).(string)
	}
	claims := map[string]any{
		"iss": iss, "sub": s.subject(), "aud": clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range s.cfg.IDTokenClaims {
		claims[k] = s.expand(v)
	}
	return s.SignJWT(claims)
}

func (s *Server) subject() string {
	if s.cfg.Subject != "" {
		return s.cfg.Subject
	}
	return "user-1"
}

// authenticateClient implements client_secret_basic (with the RFC 6749
// § 2.3.1 form-decoding of both parts), client_secret_post and none. It
// writes the error response itself and returns nil on failure.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) *Client {
	form := r.PostForm
	var id, secret string
	viaBasic := false
	if user, pass, ok := r.BasicAuth(); ok {
		u, err1 := url.QueryUnescape(user)
		p, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			s.oauthError(w, http.StatusUnauthorized, "invalid_client", "malformed basic credentials")
			return nil
		}
		id, secret, viaBasic = u, p, true
		if form.Get("client_secret") != "" {
			s.oauthError(w, http.StatusBadRequest, "invalid_request", "client credentials sent with more than one method")
			return nil
		}
		if bodyID := form.Get("client_id"); bodyID != "" && bodyID != id {
			s.oauthError(w, http.StatusBadRequest, "invalid_request", "client_id does not match the authenticated client")
			return nil
		}
	} else {
		id, secret = form.Get("client_id"), form.Get("client_secret")
	}
	if form.Get("client_assertion") != "" {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "client assertions are not supported by this test server")
		return nil
	}
	c := s.clientByID(id)
	if c == nil {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return nil
	}
	if s.cfg.Quirks.DeviceAuthWithoutSecret && secret == "" && !viaBasic && s.routeOf(r.URL.Path) == EndpointDeviceAuthorization {
		return c
	}
	switch {
	case c.Secret == "" && (secret != "" || viaBasic):
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "a public client must not send a secret")
		return nil
	case c.Secret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1:
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return nil
	}
	return c
}

// dpopClaims are the claims of a DPoP proof.
type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	ATH   string `json:"ath"`
}

// dpopError is a refused DPoP proof: the error code and description.
type dpopError struct{ code, desc string }

func (e *dpopError) Error() string { return e.code + ": " + e.desc }

var dpopAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512, jose.EdDSA,
}

// checkDPoP verifies the request's DPoP proof (RFC 9449 § 4.3) and returns
// the JWK thumbprint of its key. It returns errNoProof without a proof, and
// a *dpopError for a refused one; use_dpop_nonce comes last, after the proof
// itself checked out.
func (s *Server) checkDPoP(r *http.Request, accessToken string) (string, error) {
	values := r.Header.Values("DPoP")
	if len(values) == 0 {
		return "", errNoProof
	}
	if len(values) > 1 {
		return "", &dpopError{"invalid_dpop_proof", "more than one DPoP header"}
	}
	algs := dpopAlgs
	s.mu.Lock()
	if adv, ok := s.metadata["dpop_signing_alg_values_supported"].([]any); ok && len(adv) > 0 {
		algs = slices.DeleteFunc(slices.Clone(dpopAlgs), func(a jose.SignatureAlgorithm) bool {
			return !slices.Contains(adv, any(string(a)))
		})
	}
	s.mu.Unlock()
	jws, err := jose.ParseSignedCompact(values[0], algs)
	if err != nil || len(jws.Signatures) != 1 {
		return "", &dpopError{"invalid_dpop_proof", "malformed proof or algorithm not allowed"}
	}
	hdr := jws.Signatures[0].Header
	if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return "", &dpopError{"invalid_dpop_proof", "typ is not dpop+jwt"}
	}
	jwk := hdr.JSONWebKey
	if jwk == nil || !jwk.IsPublic() || !jwk.Valid() {
		return "", &dpopError{"invalid_dpop_proof", "jwk header missing or not a public key"}
	}
	payload, err := jws.Verify(jwk.Key)
	if err != nil {
		return "", &dpopError{"invalid_dpop_proof", "signature does not verify"}
	}
	var c dpopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", &dpopError{"invalid_dpop_proof", "claims are not JSON"}
	}
	wantHTU := s.URL + r.URL.Path
	now := s.now()
	iat := time.Unix(c.IAT, 0)
	switch {
	case c.JTI == "" || len(c.JTI) > 255:
		return "", &dpopError{"invalid_dpop_proof", "bad jti"}
	case c.HTM != r.Method:
		return "", &dpopError{"invalid_dpop_proof", "htm does not match"}
	case c.HTU != wantHTU:
		return "", &dpopError{"invalid_dpop_proof", "htu does not match"}
	case iat.Before(now.Add(-60*time.Second)) || iat.After(now.Add(5*time.Second)):
		return "", &dpopError{"invalid_dpop_proof", "iat outside the acceptable window"}
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if c.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", &dpopError{"invalid_dpop_proof", "ath does not match the access token"}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jtis[c.JTI] {
		return "", &dpopError{"invalid_dpop_proof", "jti replayed"}
	}
	s.jtis[c.JTI] = true
	if s.cfg.DPoP.RequireNonce && (c.Nonce == "" || !slices.Contains(s.nonces, c.Nonce)) {
		return "", &dpopError{"use_dpop_nonce", "a DPoP nonce is required"}
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", &dpopError{"invalid_dpop_proof", "thumbprint"}
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// newNonce mints a DPoP nonce and remembers it as valid.
func (s *Server) newNonce() string {
	n := "nonce-" + randomString(12)
	s.mu.Lock()
	s.nonces = append(s.nonces, n)
	s.mu.Unlock()
	return n
}

// requestScope splits a scope parameter.
func requestScope(raw string) []string { return strings.Fields(raw) }
