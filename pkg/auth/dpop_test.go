package auth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	ATH   string `json:"ath"`
}

// verifyProof checks a DPoP proof the way RFC 9449 § 4.3 does and returns
// its claims and the thumbprint of its key.
func verifyProof(raw string) (proofClaims, string, error) {
	var cl proofClaims
	jws, err := jose.ParseSignedCompact(raw, dpopAlgPreference)
	if err != nil {
		return cl, "", fmt.Errorf("parse: %w", err)
	}
	hdr := jws.Signatures[0].Protected
	if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return cl, "", fmt.Errorf("typ %q", typ)
	}
	if hdr.JSONWebKey == nil || !hdr.JSONWebKey.IsPublic() {
		return cl, "", errors.New("jwk header missing or private")
	}
	payload, err := jws.Verify(hdr.JSONWebKey)
	if err != nil {
		return cl, "", fmt.Errorf("signature: %w", err)
	}
	if err := json.Unmarshal(payload, &cl); err != nil {
		return cl, "", err
	}
	if cl.JTI == "" || cl.HTM == "" || cl.HTU == "" || cl.IAT == 0 {
		return cl, "", errors.New("claim missing")
	}
	tp, err := hdr.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return cl, "", err
	}
	return cl, base64.RawURLEncoding.EncodeToString(tp), nil
}

func ath(at string) string {
	sum := sha256.Sum256([]byte(at))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopAS behaves like nauthera-server at its token endpoint and a resource
// server at /api: a nonce is always required, every proof is single use,
// and a refresh token stays bound to the key it was issued for.
type dpopAS struct {
	*fakeAS
	t *testing.T

	mu          sync.Mutex
	asNonce     string
	rsNonce     string
	jtis        map[string]bool
	bound       map[string]string // access or refresh token -> jkt
	deviceJKT   string
	issueBearer bool // ignore proofs, like a server without DPoP
	checkIAT    bool
	proofs      []proofClaims
	n           int
}

func newDPoPAS(t *testing.T) *dpopAS {
	t.Helper()
	d := &dpopAS{
		fakeAS: newFakeAS(t), t: t, asNonce: "as-nonce-1", rsNonce: "rs-nonce-1",
		jtis: map[string]bool{}, bound: map[string]string{},
	}
	d.setMetadata("dpop_signing_alg_values_supported", []string{"ES256", "PS256"})
	d.setMetadata("grant_types_supported", []string{
		"authorization_code", "refresh_token", "client_credentials",
		"urn:ietf:params:oauth:grant-type:device_code",
	})
	d.handle("/token", d.token)
	d.handle("/api", d.api)
	d.handle("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.deviceJKT = r.PostForm.Get("dpop_jkt")
		d.mu.Unlock()
		writeJSONResponse(w, http.StatusOK, standardDA(d.URL))
	})
	return d
}

// proof validates the DPoP header of r. It returns the key thumbprint, or
// "" after it wrote the error response.
func (d *dpopAS) proof(w http.ResponseWriter, r *http.Request, wantHTU, nonce, accessToken string, rs bool) string {
	fail := func(code string) string {
		if rs {
			w.Header().Set("WWW-Authenticate", `DPoP error="`+code+`", algs="ES256 PS256"`)
			w.WriteHeader(http.StatusUnauthorized)
			return ""
		}
		oauthError(w, http.StatusBadRequest, code)
		return ""
	}
	cl, jkt, err := verifyProof(r.Header.Get("DPoP"))
	if err != nil {
		d.t.Logf("proof refused: %v", err)
		return fail("invalid_dpop_proof")
	}
	d.mu.Lock()
	replay := d.jtis[cl.JTI]
	d.jtis[cl.JTI] = true
	d.proofs = append(d.proofs, cl)
	d.mu.Unlock()
	switch {
	case replay:
		return fail("invalid_dpop_proof")
	case cl.HTM != r.Method || cl.HTU != wantHTU:
		d.t.Errorf("htm/htu = %s %s, want %s %s", cl.HTM, cl.HTU, r.Method, wantHTU)
		return fail("invalid_dpop_proof")
	case d.checkIAT && (time.Since(time.Unix(cl.IAT, 0)) > time.Minute || time.Until(time.Unix(cl.IAT, 0)) > 5*time.Second):
		return fail("invalid_dpop_proof")
	case accessToken != "" && cl.ATH != ath(accessToken):
		d.t.Errorf("ath does not match the access token")
		return fail("invalid_dpop_proof")
	case accessToken == "" && cl.ATH != "":
		d.t.Errorf("ath sent to the token endpoint")
	case cl.Nonce != nonce:
		return fail("use_dpop_nonce")
	}
	return jkt
}

func (d *dpopAS) token(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	nonce, bearer := d.asNonce, d.issueBearer
	d.n++
	n := d.n
	d.mu.Unlock()
	w.Header().Set("DPoP-Nonce", nonce)
	jkt := ""
	if !bearer {
		if r.Header.Get("DPoP") == "" {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof")
			return
		}
		if jkt = d.proof(w, r, d.URL+"/token", nonce, "", false); jkt == "" {
			return
		}
	}
	f := r.PostForm
	switch f.Get("grant_type") {
	case "refresh_token":
		d.mu.Lock()
		want, ok := d.bound[f.Get("refresh_token")]
		d.mu.Unlock()
		if !ok || want != jkt {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
		d.mu.Lock()
		want := d.deviceJKT
		d.mu.Unlock()
		if want != jkt {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof")
			return
		}
	}
	at, rt := fmt.Sprintf("at-%d", n), fmt.Sprintf("rt-%d", n)
	d.mu.Lock()
	d.bound[at], d.bound[rt] = jkt, jkt
	d.mu.Unlock()
	tt := "DPoP"
	if bearer {
		tt = "Bearer"
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": at, "token_type": tt, "expires_in": 600, "refresh_token": rt})
}

func (d *dpopAS) api(w http.ResponseWriter, r *http.Request) {
	scheme, at, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if scheme != "DPoP" {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	d.mu.Lock()
	nonce := d.rsNonce
	want := d.bound[at]
	d.mu.Unlock()
	w.Header().Set("DPoP-Nonce", nonce)
	jkt := d.proof(w, r, d.URL+r.URL.Path, nonce, at, true)
	if jkt == "" {
		return
	}
	if jkt != want {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _ = w.Write([]byte("hello " + at))
}

func (d *dpopAS) proofCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.proofs)
}

func TestDPoPClientCredentialsAndTransport(t *testing.T) {
	t.Parallel()
	d := newDPoPAS(t)
	env := newTestEnv(t, d.fakeAS, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoP())

	tok, err := env.client.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.TokenType != TokenTypeDPoP || tok.DPoPKey == "" {
		t.Fatalf("token not DPoP-bound: %v", tok)
	}
	// One refused proof without nonce, one accepted with it.
	if n := d.proofCount(); n != 2 {
		t.Fatalf("%d proofs at the token endpoint, want 2 (nonce retry)", n)
	}
	stored, err := env.store.Get(context.Background(), env.client.StorageKey())
	if err != nil || stored.DPoPKey != tok.DPoPKey {
		t.Fatalf("DPoP key not stored with the token: %v", err)
	}
	if strings.Contains(stored.String(), `"d"`) || strings.Contains(stored.String(), tok.DPoPKey) {
		t.Fatal("formatting a token leaks the DPoP private key")
	}

	hc := &http.Client{Transport: env.client.Transport(d.Client().Transport)}
	for i := 0; i < 2; i++ {
		resp, err := hc.Get(d.URL + "/api?x=1")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("resource request %d: HTTP %d", i, resp.StatusCode)
		}
	}
	// 2 token proofs, then the first API call needs a nonce retry (2) and
	// the second uses the cached nonce (1).
	if n := d.proofCount(); n != 5 {
		t.Fatalf("%d proofs in total, want 5", n)
	}
}

func TestDPoPDeviceFlowBindsAndRefreshKeepsKey(t *testing.T) {
	t.Parallel()
	d := newDPoPAS(t)
	store := storage.NewMemory()
	env := newTestEnv(t, d.fakeAS, WithFlow(FlowDevice), WithDPoPAuto(), WithStorage(store))

	tok, err := env.client.Login(context.Background())
	if err != nil {
		t.Fatalf("device login: %v", err)
	}
	if tok.TokenType != TokenTypeDPoP {
		t.Fatalf("token type %s", tok.TokenType)
	}
	key, err := parseDPoPKey(tok.DPoPKey)
	if err != nil {
		t.Fatal(err)
	}
	if da := d.requestsTo("/device_authorization")[0].Form.Get("dpop_jkt"); da != key.jkt {
		t.Fatalf("dpop_jkt %q does not name the stored key %q", da, key.jkt)
	}

	// A new process: a new Client reading the same store. The refresh must
	// be signed with the stored key, or nauthera refuses the bound token.
	env.clock.Advance(time.Hour)
	again := newTestEnv(t, d.fakeAS, WithFlow(FlowDevice), WithDPoPAuto(), WithStorage(store))
	again.clock.now = env.clock.Now()
	next, err := again.client.Token(context.Background())
	if err != nil {
		t.Fatalf("refresh with the stored key: %v", err)
	}
	if next.AccessToken == tok.AccessToken || next.DPoPKey != tok.DPoPKey {
		t.Fatalf("refresh did not rotate or lost the key: %v", next)
	}
}

func TestDPoPBearerDowngrade(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		opt     Option
		wantErr error
	}{
		{"required refuses", WithDPoP(), ErrDPoPNotBound},
		{"auto accepts", WithDPoPAuto(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newDPoPAS(t)
			d.issueBearer = true
			env := newTestEnv(t, d.fakeAS, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), tc.opt)
			tok, err := env.client.Login(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (tok.TokenType != TokenTypeBearer || tok.DPoPKey == "") {
				t.Fatalf("token %v", tok)
			}
		})
	}
}

func TestDPoPAutoNeedsAdvertisement(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "a", "token_type": "Bearer"})
	})
	env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoPAuto())
	if _, err := env.client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := as.requestsTo("/token")[0].Header.Get("DPoP"); h != "" {
		t.Fatal("a DPoP proof was sent to a server that does not advertise DPoP")
	}
}

func TestDPoPUnadvertisedTokenTypeRefused(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{"access_token": "a", "token_type": "DPoP"})
	})
	env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"))
	if _, err := env.client.Login(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("a DPoP token without a proof: err = %v", err)
	}
}

func TestDPoPCorrectsClockFromDateHeader(t *testing.T) {
	t.Parallel()
	d := newDPoPAS(t)
	d.checkIAT = true
	// The fake clock is years ahead of the server's.
	env := newTestEnv(t, d.fakeAS, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoP())
	if _, err := env.client.Login(context.Background()); err != nil {
		t.Fatalf("Login with a skewed clock: %v", err)
	}
}

func TestDPoPRetriesOnlyOnce(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	n := 0
	var mu sync.Mutex
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		w.Header().Set("DPoP-Nonce", fmt.Sprintf("nonce-%d", n))
		mu.Unlock()
		oauthError(w, http.StatusBadRequest, "use_dpop_nonce")
	})
	env := newTestEnv(t, as, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoP())
	if _, err := env.client.Login(context.Background()); !errors.Is(err, ErrUseDPoPNonce) {
		t.Fatalf("err = %v", err)
	}
	if got := len(as.requestsTo("/token")); got != 2 {
		t.Fatalf("%d token requests, want 2", got)
	}
}

func TestDPoPKeys(t *testing.T) {
	t.Parallel()
	for _, alg := range []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA, jose.PS256, jose.ES384} {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()
			k, err := generateDPoPKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			back, err := parseDPoPKey(k.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if back.jkt != k.jkt || back.alg != alg {
				t.Fatalf("round trip changed the key: %s %s", back.alg, back.jkt)
			}
			raw, err := back.proof(http.MethodPost, "https://as.example/token", "n", "at", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			cl, jkt, err := verifyProof(raw)
			if err != nil || jkt != k.jkt || cl.Nonce != "n" || cl.ATH != ath("at") {
				t.Fatalf("proof: %+v %s %v", cl, jkt, err)
			}
			if len(k.jkt) != 43 {
				t.Fatalf("thumbprint %q is not 43 base64url characters", k.jkt)
			}
		})
	}
	if _, err := parseDPoPKey(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`); err == nil {
		t.Fatal("a public key was accepted as a stored DPoP key")
	}
	if _, ok := chooseDPoPAlg([]string{"HS256"}); ok {
		t.Fatal("a MAC algorithm was chosen for DPoP")
	}
	if alg, _ := chooseDPoPAlg([]string{"RS256", "PS256", "ES256"}); alg != jose.ES256 {
		t.Fatalf("chose %s, want ES256", alg)
	}
}

func TestDPoPHTU(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("https://user:pw@rs.example/a/b?q=1#frag")
	if got := dpopHTU(u); got != "https://rs.example/a/b" {
		t.Fatalf("htu = %s", got)
	}
	for nonce, ok := range map[string]bool{"abc-123_~": true, "": false, "a b": false, `a"b`: false, strings.Repeat("a", 600): false} {
		if validDPoPNonce(nonce) != ok {
			t.Errorf("validDPoPNonce(%q) = %v", nonce, !ok)
		}
	}
}

func TestParseChallenges(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Add("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="the \"token\" expired"`)
	h.Add("WWW-Authenticate", `DPoP algs="ES256 PS256", error=use_dpop_nonce, Basic realm="x"`)
	h.Add("WWW-Authenticate", `Negotiate abc==, Bearer`)
	got := parseChallenges(h.Values("WWW-Authenticate"))
	if len(got) < 4 {
		t.Fatalf("challenges: %+v", got)
	}
	if got[0].scheme != "bearer" || got[0].params["error"] != "invalid_token" || got[0].params["error_description"] != `the "token" expired` {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].scheme != "dpop" || got[1].params["error"] != "use_dpop_nonce" || got[2].scheme != "basic" {
		t.Fatalf("second header: %+v", got[1:3])
	}
	if !hasChallengeError(h, "use_dpop_nonce", "dpop") || hasChallengeError(h, "use_dpop_nonce", "bearer") ||
		!hasChallengeError(h, "invalid_token") {
		t.Fatal("hasChallengeError")
	}
}

func TestDPoPTransportRefreshesAndReplaysBody(t *testing.T) {
	t.Parallel()
	d := newDPoPAS(t)
	var (
		mu     sync.Mutex
		bodies []string
		reject = true
	)
	d.handle("/upload", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		mu.Lock()
		bodies = append(bodies, string(b[:n]))
		first := reject
		reject = false
		mu.Unlock()
		if first {
			// The first access token is refused as if revoked.
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		d.api(w, r)
	})
	env := newTestEnv(t, d.fakeAS, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoP())
	if _, err := env.client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: env.client.Transport(d.Client().Transport)}
	resp, err := hc.Post(d.URL+"/upload", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) < 2 || bodies[0] != "payload" || bodies[1] != "payload" {
		t.Fatalf("request bodies on replay: %q", bodies)
	}
	stored, _ := env.store.Get(context.Background(), env.client.StorageKey())
	if stored.AccessToken == "at-2" || stored.TokenType != TokenTypeDPoP {
		t.Fatalf("the refused token was not replaced: %v", stored)
	}
}

func TestDPoPTokenWithoutKey(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	storeToken(t, env, &storage.Token{AccessToken: "at", TokenType: TokenTypeDPoP, Expiry: env.clock.Now().Add(time.Hour)})
	hc := &http.Client{Transport: env.client.Transport(as.Client().Transport)}
	_, err := hc.Get(as.URL + "/api")
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v", err)
	}
	storeToken(t, env, &storage.Token{AccessToken: "at", RefreshToken: "rt", TokenType: TokenTypeDPoP, DPoPKey: "{garbage"})
	if _, err := env.client.Refresh(context.Background(), &storage.Token{RefreshToken: "rt", DPoPKey: "{garbage"}); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("refresh with a corrupt key: %v", err)
	}
}

func TestDPoPAlgorithmNegotiation(t *testing.T) {
	t.Parallel()
	md := &Metadata{DPoPSigningAlgValuesSupported: []string{"HS256"}}
	auto := &Client{cfg: config{dpop: dpopAuto, clock: systemClock{}}}
	if k, err := auto.loginDPoPKey(context.Background(), md); k != nil || err != nil {
		t.Fatalf("auto with no usable algorithm: %v %v", k, err)
	}
	req := &Client{cfg: config{dpop: dpopRequired, clock: systemClock{}}}
	if _, err := req.loginDPoPKey(context.Background(), md); !errors.Is(err, ErrUnsupportedFlow) {
		t.Fatalf("required with no usable algorithm: %v", err)
	}
	k, err := req.loginDPoPKey(context.Background(), &Metadata{DPoPSigningAlgValuesSupported: []string{"EdDSA", "RS256"}})
	if err != nil || k.alg != jose.EdDSA {
		t.Fatalf("negotiated %v, %v", k, err)
	}
	if _, err := generateDPoPKey(jose.HS256); err == nil {
		t.Fatal("a MAC key was generated for DPoP")
	}
}

func TestTokenCommandNotesDPoP(t *testing.T) {
	t.Parallel()
	d := newDPoPAS(t)
	store := storage.NewMemory()
	opts := cmdOptions(d.fakeAS, store, WithFlow(FlowClientCredentials), WithClientSecret("s3cret"), WithDPoP())
	if _, _, err := runCommand(t, NewLoginCommand(opts...)); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runCommand(t, NewTokenCommand(opts...))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout, "at-") || !strings.Contains(stderr, "DPoP-bound") {
		t.Fatalf("stdout %q, stderr %q", stdout, stderr)
	}
}
