package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

const (
	testAudience = "https://api.example.com"
	nativeID     = "auth0-native-cli"
	m2mID        = "auth0-m2m"
	m2mSecret    = "m2m-secret-value"
)

// fakeAuth0 serves Auth0's discovery document from an issuer with a trailing
// slash, signs with RS256 and answers device polls with 403, as Auth0 does.
func fakeAuth0(t *testing.T) *oauthtest.Server {
	t.Helper()
	return oauthtest.New(t, oauthtest.Config{
		TLS:        true,
		IssuerPath: "/",
		Metadata:   oauthtest.LoadJSON(t, "../../../pkg/auth/testdata/providers/auth0/discovery.json"),
		Discovery:  oauthtest.DiscoveryOIDC,
		SigningAlg: "RS256",
		Clients: []oauthtest.Client{
			{ID: nativeID, RedirectURIs: []string{"http://127.0.0.1:8484/callback"}},
			{ID: m2mID, Secret: m2mSecret, Grants: []string{"client_credentials"}},
		},
		RefreshScope:   "offline_access",
		DeviceInterval: 1,
		Quirks: oauthtest.Quirks{ErrorStatus: map[string]int{
			"authorization_pending": 403, "slow_down": 429, "expired_token": 403, "access_denied": 403,
		}},
	})
}

// env returns a getenv for the tenant at srv.
func env(srv *oauthtest.Server, vars map[string]string) func(string) string {
	all := map[string]string{
		"AUTH0_DOMAIN":   strings.TrimPrefix(srv.URL, "https://"),
		"AUTH0_AUDIENCE": testAudience,
	}
	for k, v := range vars {
		all[k] = v
	}
	return func(k string) string { return all[k] }
}

// run executes the example's command tree with args, sharing store between
// runs as the keyring would.
func run(t *testing.T, srv *oauthtest.Server, getenv func(string) string, store storage.Provider, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRootCommand(getenv,
		auth.WithHTTPClient(srv.Client()),
		auth.WithStorage(store),
		auth.WithBrowser(false),
	)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

func TestDeviceLoginSendsTheAudience(t *testing.T) {
	t.Parallel()
	srv := fakeAuth0(t)
	getenv := env(srv, map[string]string{"AUTH0_CLIENT_ID": nativeID})
	store := storage.NewMemory()

	if _, stderr, err := run(t, srv, getenv, store, "auth", "login", "--flow", "device", "--no-browser"); err != nil {
		t.Fatalf("login: %v\n%s", err, stderr)
	}
	reqs := srv.Requests(oauthtest.EndpointDeviceAuthorization)
	if len(reqs) != 1 || reqs[0].Form.Get("audience") != testAudience {
		t.Fatalf("device authorization requests %+v, want one with audience %s", reqs, testAudience)
	}
	if scope := reqs[0].Form.Get("scope"); !strings.Contains(scope, "offline_access") {
		t.Fatalf("scope %q lacks offline_access, so Auth0 would issue no refresh token", scope)
	}

	stdout, _, err := run(t, srv, getenv, store, "auth", "status")
	if err != nil || !strings.Contains(stdout, "Refresh token: yes") {
		t.Fatalf("status after login: %v\n%s", err, stdout)
	}
	token, _, err := run(t, srv, getenv, store, "auth", "token")
	if err != nil || strings.TrimSpace(token) == "" || strings.Contains(strings.TrimSpace(token), "\n") {
		t.Fatalf("token printed %q: %v", token, err)
	}
}

func TestClientCredentialsWithASecret(t *testing.T) {
	t.Parallel()
	srv := fakeAuth0(t)
	getenv := env(srv, map[string]string{"AUTH0_CLIENT_ID": m2mID, "AUTH0_CLIENT_SECRET": m2mSecret})

	stdout, stderr, err := run(t, srv, getenv, storage.NewMemory(), "auth", "token")
	if err != nil {
		t.Fatalf("token: %v\n%s", err, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("no token printed")
	}
	if strings.Contains(stdout+stderr, m2mSecret) {
		t.Fatal("the client secret was printed")
	}
	reqs := srv.Requests(oauthtest.EndpointToken)
	if len(reqs) != 1 {
		t.Fatalf("%d token requests, want 1", len(reqs))
	}
	if got := reqs[0].Form.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q", got)
	}
	if got := reqs[0].Form.Get("audience"); got != testAudience {
		t.Fatalf("audience = %q", got)
	}
	if n := len(srv.Requests(oauthtest.EndpointDeviceAuthorization)); n != 0 {
		t.Fatalf("a machine client started %d device authorizations", n)
	}
}

func TestMissingDomainIsAConfigurationError(t *testing.T) {
	t.Parallel()
	srv := fakeAuth0(t)
	getenv := func(k string) string {
		if k == "AUTH0_CLIENT_ID" {
			return nativeID
		}
		return ""
	}
	if _, _, err := run(t, srv, getenv, storage.NewMemory(), "auth", "token"); err == nil ||
		!strings.Contains(err.Error(), "Auth0") {
		t.Fatalf("token without AUTH0_DOMAIN: %v", err)
	}
	if n := len(srv.Requests(oauthtest.EndpointDiscovery)); n != 0 {
		t.Fatalf("%d discovery requests for an invalid configuration", n)
	}
}

func TestGetRefusesPlainHTTP(t *testing.T) {
	t.Parallel()
	srv := fakeAuth0(t)
	getenv := env(srv, map[string]string{"AUTH0_CLIENT_ID": nativeID})
	if _, _, err := run(t, srv, getenv, storage.NewMemory(), "get", "http://api.example.com/"); err == nil ||
		!strings.Contains(err.Error(), "not an https URL") {
		t.Fatalf("get with http: %v", err)
	}
}
