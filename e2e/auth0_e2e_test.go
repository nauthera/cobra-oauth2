//go:build e2e

package e2e

// Live tests against an Auth0 tenant, beside the nauthera ones: the same
// library, a provider with its own quirks (an issuer with a trailing slash,
// the audience parameter, RS256 JWT access tokens). They skip unless the
// tenant and a Machine to Machine application are configured:
//
//	AUTH0_DOMAIN or       the tenant domain, or its OpenID Connect discovery
//	AUTH0_DISCOVERY_URL   URL, from which the domain is taken
//	AUTH0_CLIENT_ID       a Machine to Machine application authorized for the API
//	AUTH0_CLIENT_SECRET   its secret
//	AUTH0_AUDIENCE        the API's identifier
//	AUTH0_DEVICE_CLIENT_ID  optional: a Native application with the Device
//	                      Code grant; enables the device flow test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

type auth0Settings struct {
	domain, clientID, secret, audience, deviceClientID string
}

func loadAuth0(t *testing.T) auth0Settings {
	t.Helper()
	s := auth0Settings{
		domain:         os.Getenv("AUTH0_DOMAIN"),
		clientID:       os.Getenv("AUTH0_CLIENT_ID"),
		secret:         os.Getenv("AUTH0_CLIENT_SECRET"),
		audience:       os.Getenv("AUTH0_AUDIENCE"),
		deviceClientID: os.Getenv("AUTH0_DEVICE_CLIENT_ID"),
	}
	if s.domain == "" {
		if u, err := url.Parse(os.Getenv("AUTH0_DISCOVERY_URL")); err == nil {
			s.domain = u.Host
		}
	}
	if s.domain == "" || s.clientID == "" || s.secret == "" || s.audience == "" {
		t.Skip("set AUTH0_DOMAIN (or AUTH0_DISCOVERY_URL), AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET and AUTH0_AUDIENCE to run the Auth0 tests (e2e/README.md)")
	}
	return s
}

func (s auth0Settings) client(t *testing.T, opts ...auth.Option) *auth.Client {
	t.Helper()
	base := []auth.Option{
		auth.Auth0(s.domain, s.audience),
		auth.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		auth.WithStorage(storage.NewMemory()),
		auth.WithBrowser(false),
		auth.WithAppName("cobra-oauth2-e2e"),
	}
	c, err := auth.NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestAuth0Discovery(t *testing.T) {
	s := loadAuth0(t)
	c := s.client(t, auth.WithClientID(s.clientID))
	md, err := c.Metadata(t.Context())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	// The preset keeps the trailing slash Auth0 publishes; the issuer check
	// is exact, so discovery would have failed above without it.
	if want := "https://" + s.domain + "/"; md.Issuer != want {
		t.Fatalf("issuer %q, want %q", md.Issuer, want)
	}
	if md.TokenEndpoint == "" || md.JWKSURI == "" {
		t.Fatalf("metadata lacks endpoints: %+v", md)
	}
}

func TestAuth0ClientCredentials(t *testing.T) {
	s := loadAuth0(t)
	c := s.client(t, auth.WithClientID(s.clientID), auth.WithClientSecret(s.secret),
		auth.WithFlow(auth.FlowClientCredentials), auth.WithScopes())
	tok, err := c.Login(t.Context())
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken != "" || tok.Expiry.IsZero() {
		t.Fatalf("token set: %v", tok)
	}
	// With an audience Auth0 issues a JWT for that API, not an opaque
	// token for /userinfo: its aud names the API.
	if aud := jwtAudience(t, tok.AccessToken); !slices.Contains(aud, s.audience) {
		t.Fatalf("access token aud %v does not name %s", aud, s.audience)
	}
	if got := c.StorageKey().Audience; got != s.audience {
		t.Fatalf("token stored under audience %q, want %q", got, s.audience)
	}

	bad := s.client(t, auth.WithClientID(s.clientID), auth.WithClientSecret(s.secret+"-wrong"),
		auth.WithFlow(auth.FlowClientCredentials), auth.WithScopes())
	if _, err := bad.Login(t.Context()); err == nil {
		t.Fatal("a wrong secret was accepted")
	} else if strings.Contains(err.Error(), s.secret) {
		t.Fatal("the error repeats the client secret")
	}
}

func TestAuth0DeviceAuthorizationPending(t *testing.T) {
	s := loadAuth0(t)
	if s.deviceClientID == "" {
		t.Skip("set AUTH0_DEVICE_CLIENT_ID (a Native application with the Device Code grant) for the device flow test")
	}
	c := s.client(t, auth.WithClientID(s.deviceClientID), auth.WithFlow(auth.FlowDevice))
	da, err := c.StartDeviceAuthorization(t.Context())
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	if da.UserCode == "" || da.VerificationURI == "" {
		t.Fatalf("device authorization: %+v", da)
	}
}

// jwtAudience returns the aud claim of a JWT without verifying it: the test
// only checks which API Auth0 issued the token for.
func jwtAudience(t *testing.T, raw string) []string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("the access token is not a JWT (%d parts); is AUTH0_AUDIENCE an API identifier?", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload: %v", err)
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("JWT claims: %v", err)
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(claims.Aud, &many)
	return many
}
