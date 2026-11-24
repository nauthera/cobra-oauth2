package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifyIDToken(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as)
	now := env.clock.Now()
	ctx := context.Background()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	with := func(mut func(c map[string]any)) string {
		c := as.validClaims(now)
		mut(c)
		return as.idToken(c)
	}
	noneToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+as.URL+`","sub":"u","aud":"`+testClientID+`","exp":9999999999}`)) + "."

	cases := []struct {
		name  string
		raw   string
		nonce string
		ok    bool
	}{
		{"valid", with(func(map[string]any) {}), "", true},
		{"valid with nonce", with(func(c map[string]any) { c["nonce"] = "n-1" }), "n-1", true},
		{"aud array with azp", with(func(c map[string]any) { c["aud"] = []string{testClientID, "api"}; c["azp"] = testClientID }), "", true},
		{"within leeway", with(func(c map[string]any) { c["exp"] = now.Add(-30 * time.Second).Unix() }), "", true},
		{"wrong issuer", with(func(c map[string]any) { c["iss"] = "https://evil.example" }), "", false},
		{"wrong audience", with(func(c map[string]any) { c["aud"] = "someone-else" }), "", false},
		{"several audiences without azp", with(func(c map[string]any) { c["aud"] = []string{testClientID, "api"} }), "", false},
		{"azp is another client", with(func(c map[string]any) { c["azp"] = "other" }), "", false},
		{"expired", with(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Hour).Unix() }), "", false},
		{"no exp", with(func(c map[string]any) { delete(c, "exp") }), "", false},
		{"issued in the future", with(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }), "", false},
		{"nonce mismatch", with(func(c map[string]any) { c["nonce"] = "other" }), "n-1", false},
		{"nonce missing", with(func(map[string]any) {}), "n-1", false},
		{"no sub", with(func(c map[string]any) { delete(c, "sub") }), "", false},
		{"alg none", noneToken, "", false},
		{"HS256 with a guessable key", signJWT(t, jose.HS256, []byte("client-secret-used-as-hmac-key!!"), as.validClaims(now)), "", false},
		{"signed by an unknown key", signJWT(t, jose.ES256, jose.JSONWebKey{Key: otherKey, KeyID: "k1"}, as.validClaims(now)), "", false},
		{"unknown kid", signJWT(t, jose.ES256, jose.JSONWebKey{Key: as.key, KeyID: "rotated"}, as.validClaims(now)), "", false},
		{"not a JWT", "abc.def", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := env.client.VerifyIDToken(ctx, tc.raw, tc.nonce)
			if tc.ok {
				if err != nil {
					t.Fatalf("VerifyIDToken: %v", err)
				}
				if claims.Subject != "user-1" || claims.Email != "user@example.com" {
					t.Fatalf("claims: %+v", claims)
				}
				return
			}
			if !errors.Is(err, ErrInvalidIDToken) {
				t.Fatalf("err = %v, want ErrInvalidIDToken", err)
			}
		})
	}
	if n := len(as.requestsTo("/jwks")); n != 1 {
		t.Fatalf("JWKS fetched %d times; it must be cached (and refetches rate-limited)", n)
	}
}

func TestVerifyIDTokenAlgorithmFromMetadata(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("id_token_signing_alg_values_supported", []string{"RS256"})
	env := newTestEnv(t, as)
	// The server says RS256 only, so an ES256 token is refused even though
	// the key would verify it.
	if _, err := env.client.VerifyIDToken(context.Background(), as.idToken(as.validClaims(env.clock.Now())), ""); !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("err = %v", err)
	}
	as2 := newFakeAS(t)
	as2.setMetadata("id_token_signing_alg_values_supported", []string{"HS256", "none"})
	env2 := newTestEnv(t, as2)
	if _, err := env2.client.VerifyIDToken(context.Background(), as2.idToken(as2.validClaims(env2.clock.Now())), ""); !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestIDTokenIssuerExceptions(t *testing.T) {
	t.Parallel()
	md := &Metadata{Issuer: "https://login.microsoftonline.com/{tenantid}/v2.0"}
	entra := &Client{cfg: config{tenantIssuer: true}}
	if !entra.idTokenIssuerOK(md, &rawClaims{Iss: "https://login.microsoftonline.com/abc/v2.0", Tid: "abc"}) {
		t.Fatal("Entra tid substitution refused")
	}
	if entra.idTokenIssuerOK(md, &rawClaims{Iss: "https://login.microsoftonline.com/abc/v2.0", Tid: "xyz"}) {
		t.Fatal("iss accepted with a different tid")
	}
	if (&Client{}).idTokenIssuerOK(md, &rawClaims{Iss: "https://login.microsoftonline.com/abc/v2.0", Tid: "abc"}) {
		t.Fatal("tid substitution without the Entra preset")
	}
	google := &Client{cfg: config{issuerAliases: []string{"accounts.google.com"}}}
	if !google.idTokenIssuerOK(&Metadata{Issuer: "https://accounts.google.com"}, &rawClaims{Iss: "accounts.google.com"}) {
		t.Fatal("Google's legacy issuer refused")
	}
}
