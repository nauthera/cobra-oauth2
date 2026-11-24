package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// DPoP (RFC 9449) support: per-login key pairs, proof JWTs, the server
// nonce and clock corrections, and binding checks on token responses.

type dpopMode int

const (
	dpopOff dpopMode = iota
	dpopAuto
	dpopRequired
)

const (
	dpopHeader      = "DPoP"
	dpopNonceHeader = "DPoP-Nonce"
	dpopProofType   = "dpop+jwt"
	// dpopClockThreshold is how far a server's Date header may differ from
	// the local clock before later proofs to that server correct their iat.
	// Date has a resolution of one second, so smaller differences are noise.
	dpopClockThreshold = 2 * time.Second
	// maxDPoPNonceLen bounds a nonce kept from a server.
	maxDPoPNonceLen = 512
	// maxDPoPOrigins bounds the per-origin nonce and clock cache.
	maxDPoPOrigins = 64
	// dpopRSABits is the size of generated RSA keys (RFC 7518 § 3.3).
	dpopRSABits = 2048
)

// dpopAlgPreference is the order in which a signing algorithm is picked
// from those a server advertises: ES256 first, as RFC 9449's examples and
// every major implementation use it.
var dpopAlgPreference = []jose.SignatureAlgorithm{
	jose.ES256, jose.EdDSA, jose.PS256, jose.RS256, jose.ES384, jose.ES512,
}

// dpopKey is a DPoP key pair with what proofs need from it.
type dpopKey struct {
	priv    crypto.Signer
	alg     jose.SignatureAlgorithm
	jkt     string // RFC 7638 SHA-256 thumbprint of the public key
	encoded string // the private JWK, as stored in storage.Token.DPoPKey
}

// chooseDPoPAlg picks the algorithm for a new key from the server's
// dpop_signing_alg_values_supported. With none advertised it is ES256.
func chooseDPoPAlg(advertised []string) (jose.SignatureAlgorithm, bool) {
	if len(advertised) == 0 {
		return jose.ES256, true
	}
	for _, a := range dpopAlgPreference {
		if slices.Contains(advertised, string(a)) {
			return a, true
		}
	}
	return "", false
}

// generateDPoPKey creates a new key pair for alg.
func generateDPoPKey(alg jose.SignatureAlgorithm) (*dpopKey, error) {
	var (
		priv crypto.Signer
		err  error
	)
	switch alg {
	case jose.ES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.ES512:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case jose.EdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case jose.PS256, jose.RS256:
		priv, err = rsa.GenerateKey(rand.Reader, dpopRSABits)
	default:
		return nil, fmt.Errorf("unsupported DPoP algorithm %s", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generate DPoP key: %w", err)
	}
	return newDPoPKey(priv, alg)
}

func newDPoPKey(priv crypto.Signer, alg jose.SignatureAlgorithm) (*dpopKey, error) {
	enc, err := (&jose.JSONWebKey{Key: priv, Algorithm: string(alg), Use: "sig"}).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encode DPoP key: %w", err)
	}
	tp, err := (&jose.JSONWebKey{Key: priv.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("DPoP key thumbprint: %w", err)
	}
	return &dpopKey{priv: priv, alg: alg, jkt: base64.RawURLEncoding.EncodeToString(tp), encoded: string(enc)}, nil
}

// parseDPoPKey decodes a key stored in storage.Token.DPoPKey.
func parseDPoPKey(encoded string) (*dpopKey, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(encoded)); err != nil {
		return nil, fmt.Errorf("stored DPoP key: %w", err)
	}
	priv, ok := jwk.Key.(crypto.Signer)
	if !ok || jwk.IsPublic() || !jwk.Valid() {
		return nil, errors.New("stored DPoP key is not a private signing key")
	}
	alg := jose.SignatureAlgorithm(jwk.Algorithm)
	if !slices.Contains(dpopAlgPreference, alg) {
		return nil, fmt.Errorf("stored DPoP key has unsupported algorithm %q", jwk.Algorithm)
	}
	return newDPoPKey(priv, alg)
}

// proof mints a DPoP proof JWT (RFC 9449 § 4.2) for one request. ath binds
// it to an access token on resource requests (§ 7.1).
func (k *dpopKey) proof(htm, htu, nonce, accessToken string, iat time.Time) (string, error) {
	jti, err := randomToken(16)
	if err != nil {
		return "", err
	}
	claims := map[string]any{"jti": jti, "htm": htm, "htu": htu, "iat": iat.Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("DPoP proof claims: %w", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: k.priv},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(dpopProofType))
	if err != nil {
		return "", fmt.Errorf("DPoP signer: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize DPoP proof: %w", err)
	}
	return raw, nil
}

// dpopHTU is the htu claim for target: the URI without query and fragment
// (RFC 9449 § 4.2).
func dpopHTU(target *url.URL) string {
	u := *target
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
	u.User = nil
	return u.String()
}

func originOf(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// dpopOrigin is what the client learned from one server: its latest nonce
// and how far its clock is from ours.
type dpopOrigin struct {
	nonce  string
	offset time.Duration
}

// validDPoPNonce checks a DPoP-Nonce value against RFC 9449 § 8.1's
// NQCHAR grammar and a length bound.
func validDPoPNonce(n string) bool {
	if n == "" || len(n) > maxDPoPNonceLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// dpopProof mints a proof for a request to target with the nonce and clock
// correction known for its origin, and returns the nonce it used.
func (c *Client) dpopProof(key *dpopKey, method string, target *url.URL, accessToken string) (proof, nonce string, err error) {
	c.dpopMu.Lock()
	st := c.dpopOrigins[originOf(target)]
	c.dpopMu.Unlock()
	iat := c.now()
	if st != nil {
		nonce = st.nonce
		iat = iat.Add(st.offset)
	}
	proof, err = key.proof(method, dpopHTU(target), nonce, accessToken, iat)
	return proof, nonce, err
}

// observeDPoP learns from a response: a DPoP-Nonce header replaces the
// cached nonce (from every response, errors included, RFC 9449 § 8.2), and
// a Date header far from the local clock corrects the iat of later proofs.
// It reports whether the nonce differs from sentNonce and whether the clock
// correction moved.
func (c *Client) observeDPoP(target *url.URL, h http.Header, sentNonce string) (newNonce, clockMoved bool) {
	c.dpopMu.Lock()
	defer c.dpopMu.Unlock()
	o := originOf(target)
	st := c.dpopOrigins[o]
	if st == nil {
		if c.dpopOrigins == nil || len(c.dpopOrigins) >= maxDPoPOrigins {
			c.dpopOrigins = make(map[string]*dpopOrigin)
		}
		st = &dpopOrigin{}
		c.dpopOrigins[o] = st
	}
	if n := h.Get(dpopNonceHeader); validDPoPNonce(n) {
		st.nonce = n
		newNonce = n != sentNonce
	}
	if d := h.Get("Date"); d != "" {
		if t, err := http.ParseTime(d); err == nil {
			measured := t.Sub(c.now())
			if (measured - st.offset).Abs() > dpopClockThreshold {
				if measured.Abs() <= dpopClockThreshold {
					measured = 0
				}
				st.offset = measured
				clockMoved = true
			}
		}
	}
	return newNonce, clockMoved
}

// dpopMiddleware adds a proof made with key to every attempt of a
// back-channel request, and retries once when the server asks for a nonce
// (use_dpop_nonce with a DPoP-Nonce header, RFC 9449 § 8) and once when it
// refuses the proof while its Date header shows the client's clock is off.
// Each attempt carries a new proof: servers keep a replay cache of jti.
func (c *Client) dpopMiddleware(key *dpopKey, next EndpointHandler) EndpointHandler {
	return func(ctx context.Context, in *EndpointRequest) (*EndpointResponse, error) {
		target, err := url.Parse(in.URL)
		if err != nil {
			return nil, fmt.Errorf("%s endpoint: %w", in.Kind, err)
		}
		retriedNonce, retriedClock := false, false
		for {
			req := &EndpointRequest{Kind: in.Kind, URL: in.URL, Form: cloneValues(in.Form), Header: in.Header.Clone()}
			proof, sent, err := c.dpopProof(key, http.MethodPost, target, "")
			if err != nil {
				return nil, err
			}
			req.Header.Set(dpopHeader, proof)
			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}
			newNonce, clockMoved := c.observeDPoP(target, resp.Header, sent)
			code := ""
			if resp.StatusCode >= 400 {
				if fields, err := parseFields(resp); err == nil {
					code = stringField(fields, "error")
				}
			}
			switch {
			case code == "use_dpop_nonce" && newNonce && !retriedNonce:
				retriedNonce = true
				c.logger().DebugContext(ctx, "DPoP: retrying with the server's nonce", "endpoint", string(in.Kind))
			case code == "invalid_dpop_proof" && clockMoved && !retriedClock:
				retriedClock = true
				c.logger().DebugContext(ctx, "DPoP: retrying with the server's clock", "endpoint", string(in.Kind))
			default:
				return resp, nil
			}
		}
	}
}

// loginDPoPKey returns a new key for a login when DPoP is in use with this
// server, or nil when it is not.
func (c *Client) loginDPoPKey(ctx context.Context, md *Metadata) (*dpopKey, error) {
	switch c.cfg.dpop {
	case dpopOff:
		return nil, nil
	case dpopAuto:
		if len(md.DPoPSigningAlgValuesSupported) == 0 {
			return nil, nil
		}
	}
	alg, ok := chooseDPoPAlg(md.DPoPSigningAlgValuesSupported)
	if !ok {
		if c.cfg.dpop == dpopAuto {
			c.logger().WarnContext(ctx, "DPoP: the server advertises no algorithm this client supports; using Bearer tokens",
				"algs", md.DPoPSigningAlgValuesSupported)
			return nil, nil
		}
		return nil, fmt.Errorf("%w: DPoP: the server supports none of the algorithms this client signs with", ErrUnsupportedFlow)
	}
	return generateDPoPKey(alg)
}

// tokenDPoPKey returns the DPoP key stored with tok, nil when there is
// none. A DPoP token without its key cannot be used or refreshed.
func (c *Client) tokenDPoPKey(tok *storage.Token) (*dpopKey, error) {
	if tok.DPoPKey == "" {
		if tok.TokenType == TokenTypeDPoP {
			return nil, fmt.Errorf("%w: the DPoP-bound token was stored without its key", ErrLoginRequired)
		}
		return nil, nil
	}
	c.dpopMu.Lock()
	defer c.dpopMu.Unlock()
	if c.dpopCached != nil && c.dpopCached.encoded == tok.DPoPKey {
		return c.dpopCached, nil
	}
	key, err := parseDPoPKey(tok.DPoPKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoginRequired, err)
	}
	c.dpopCached = key
	return key, nil
}

// bindDPoP records key in a newly issued token set and checks the binding:
// a DPoP token needs the key it was issued for, and with [WithDPoP] a login
// that yields a Bearer token fails. login is false for refreshes, where the
// rotated refresh token must not be thrown away.
func (c *Client) bindDPoP(ctx context.Context, tok *storage.Token, key *dpopKey, login bool) error {
	if key == nil {
		if tok.TokenType == TokenTypeDPoP {
			return fmt.Errorf("%w: a DPoP token was issued to a request without a proof", ErrInvalidResponse)
		}
		return nil
	}
	tok.DPoPKey = key.encoded
	if tok.TokenType == TokenTypeDPoP {
		return nil
	}
	if login && c.cfg.dpop == dpopRequired {
		return fmt.Errorf("%w: token_type is %s", ErrDPoPNotBound, tok.TokenType)
	}
	c.logger().WarnContext(ctx, "DPoP: the server issued a Bearer token although a proof was sent")
	return nil
}

// challenge is one parsed WWW-Authenticate challenge (RFC 9110 § 11.6.1).
type challenge struct {
	scheme string            // lower case
	params map[string]string // names in lower case
}

func isTChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
}

type challengeLexer struct {
	s string
	i int
}

func (l *challengeLexer) done() bool { return l.i >= len(l.s) }

func (l *challengeLexer) skip(chars string) {
	for !l.done() && strings.IndexByte(chars, l.s[l.i]) >= 0 {
		l.i++
	}
}

func (l *challengeLexer) peek(b byte) bool { return !l.done() && l.s[l.i] == b }

func (l *challengeLexer) token() string {
	start := l.i
	for !l.done() && isTChar(l.s[l.i]) {
		l.i++
	}
	return l.s[start:l.i]
}

func (l *challengeLexer) quoted() string {
	l.i++ // opening quote
	var b strings.Builder
	for !l.done() {
		c := l.s[l.i]
		l.i++
		switch {
		case c == '\\' && !l.done():
			b.WriteByte(l.s[l.i])
			l.i++
		case c == '"':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// parseChallenges parses WWW-Authenticate header values into challenges.
// It is lenient: a token68 credential or malformed tail ends the parse of
// that header without failing, since only a few parameters matter here.
func parseChallenges(values []string) []challenge {
	var out []challenge
	for _, v := range values {
		l := &challengeLexer{s: v}
		for {
			l.skip(" \t,")
			scheme := l.token()
			if scheme == "" {
				break
			}
			ch := challenge{scheme: strings.ToLower(scheme), params: map[string]string{}}
			for {
				l.skip(" \t")
				save := l.i
				name := l.token()
				l.skip(" \t")
				if name == "" || !l.peek('=') {
					// The next challenge's scheme, or the end.
					l.i = save
					break
				}
				l.i++
				l.skip(" \t")
				val := ""
				if l.peek('"') {
					val = l.quoted()
				} else {
					val = l.token()
				}
				ch.params[strings.ToLower(name)] = val
				l.skip(" \t")
				if !l.peek(',') {
					break
				}
				l.i++
			}
			// A token68 credential or garbage leaves a character that
			// starts no token, which ends this header at the top of the
			// loop.
			out = append(out, ch)
		}
	}
	return out
}

// hasChallengeError reports whether a WWW-Authenticate header carries a
// challenge with the given error, for any of the schemes (all when none).
func hasChallengeError(h http.Header, code string, schemes ...string) bool {
	for _, ch := range parseChallenges(h.Values("WWW-Authenticate")) {
		if len(schemes) > 0 && !slices.Contains(schemes, ch.scheme) {
			continue
		}
		if ch.params["error"] == code {
			return true
		}
	}
	return false
}
