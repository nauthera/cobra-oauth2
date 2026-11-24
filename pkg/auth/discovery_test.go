package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestMetadataURLs(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"https://as.example": {
			"https://as.example/.well-known/openid-configuration",
			"https://as.example/.well-known/oauth-authorization-server",
		},
		// Auth0 publishes its issuer with a trailing slash.
		"https://tenant.auth0.com/": {
			"https://tenant.auth0.com/.well-known/openid-configuration",
			"https://tenant.auth0.com/.well-known/oauth-authorization-server",
		},
		// nauthera tenant organizations: both styles are served.
		"https://as.example/orgs/acme": {
			"https://as.example/orgs/acme/.well-known/openid-configuration",
			"https://as.example/.well-known/oauth-authorization-server/orgs/acme",
		},
	}
	for issuer, want := range cases {
		got, err := MetadataURLs(issuer)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("MetadataURLs(%q) = %v, want %v", issuer, got, want)
		}
	}
	if _, err := MetadataURLs("https://as.example/?x=1"); err == nil {
		t.Error("issuer with a query accepted")
	}
}

func TestIssuerFromDiscoveryURL(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://as.example/.well-known/openid-configuration":                 "https://as.example",
		"https://as.example/orgs/acme/.well-known/openid-configuration":       "https://as.example/orgs/acme",
		"https://as.example/.well-known/oauth-authorization-server/orgs/acme": "https://as.example/orgs/acme",
		"https://as.example/.well-known/oauth-authorization-server":           "https://as.example",
	}
	for in, want := range cases {
		got, err := issuerFromDiscoveryURL(in)
		if err != nil || got != want {
			t.Errorf("issuerFromDiscoveryURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := issuerFromDiscoveryURL("https://as.example/config.json"); err == nil {
		t.Error("URL without a well-known suffix accepted")
	}
}

func TestNewClientDoesNoIO(t *testing.T) {
	t.Parallel()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	if _, err := NewClient(WithIssuer(srv.URL), WithClientID("c"), WithHTTPClient(srv.Client())); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(WithIssuer("https://unreachable.invalid"), WithClientID("c")); err != nil {
		t.Fatalf("an unreachable issuer must not fail construction: %v", err)
	}
	if hits != 0 {
		t.Fatalf("NewClient made %d requests", hits)
	}
}

func TestDiscoveryCachesAndOverrides(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	env := newTestEnv(t, as, WithRevocationEndpoint("https://revoke.example/revoke"))
	ctx := context.Background()
	for range 3 {
		md, err := env.client.Metadata(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if md.TokenEndpoint != as.URL+"/token" || md.RevocationEndpoint != "https://revoke.example/revoke" {
			t.Fatalf("metadata: %+v", md)
		}
	}
	if n := len(as.requestsTo("/.well-known/openid-configuration")); n != 1 {
		t.Fatalf("discovery fetched %d times, want 1", n)
	}
}

func TestDiscoveryFallsBackToRFC8414(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer := srv.URL + "/orgs/acme"
	mux.HandleFunc("/.well-known/oauth-authorization-server/orgs/acme", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]any{"issuer": issuer, "token_endpoint": issuer + "/token"})
	})
	c, err := NewClient(WithIssuer(issuer), WithClientID("c"), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.TokenEndpoint != issuer+"/token" {
		t.Fatalf("token endpoint %q", md.TokenEndpoint)
	}
}

func TestDiscoveryRefusesBadDocuments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(as *fakeAS)
		wantErr error
	}{
		{"issuer mismatch", func(as *fakeAS) { as.setMetadata("issuer", "https://evil.example") }, ErrIssuerMismatch},
		{"issuer with trailing slash differs", func(as *fakeAS) { as.setMetadata("issuer", as.URL+"/") }, ErrIssuerMismatch},
		{"plain-http token endpoint", func(as *fakeAS) { as.setMetadata("token_endpoint", "http://evil.example/token") }, ErrInsecureEndpoint},
		{"javascript device endpoint", func(as *fakeAS) { as.setMetadata("device_authorization_endpoint", "javascript:alert(1)") }, ErrInsecureEndpoint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			as := newFakeAS(t)
			tc.mutate(as)
			env := newTestEnv(t, as)
			_, err := env.client.Metadata(context.Background())
			if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrDiscovery) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			// A mismatch stops the search: the RFC 8414 location is not tried.
			if n := len(as.requestsTo("/.well-known/oauth-authorization-server")); n != 0 {
				t.Fatalf("kept searching after a refused document (%d requests)", n)
			}
		})
	}
}

func TestDiscoveryRefusesNonJSONAndErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, err := NewClient(WithIssuer(srv.URL), WithClientID("c"), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Metadata(context.Background())
	if !errors.Is(err, ErrDiscovery) || strings.Contains(err.Error(), "login") {
		t.Fatalf("err = %v", err)
	}
}

func TestEntraTenantTemplateIssuer(t *testing.T) {
	t.Parallel()
	c := &Client{cfg: config{tenantIssuer: true}}
	tmpl := "https://login.microsoftonline.com/{tenantid}/v2.0"
	if !c.issuerMatches("https://login.microsoftonline.com/common/v2.0", tmpl) {
		t.Fatal("template not accepted for the multi-tenant issuer")
	}
	if c.issuerMatches("https://evil.example/common/v2.0", tmpl) {
		t.Fatal("template matched another host")
	}
	if c.issuerMatches("https://login.microsoftonline.com/a/b/v2.0", tmpl) {
		t.Fatal("template matched several path segments")
	}
	if (&Client{}).issuerMatches("https://login.microsoftonline.com/common/v2.0", tmpl) {
		t.Fatal("template accepted without the Entra preset")
	}
	// Prefix and suffix overlap inside want: this used to slice out of
	// range and panic.
	for _, want := range []string{
		"https://login.microsoftonline.com/v2.0",
		"https://login.microsoftonline.com//v2.0",
		"https://login.microsoftonline.com/",
		"",
	} {
		if c.issuerMatches(want, tmpl) {
			t.Errorf("issuerMatches(%q) = true", want)
		}
	}
	if c.issuerMatches("ab", "a{tenantid}b") || c.issuerMatches("aba", "ab{tenantid}ba") {
		t.Error("overlapping prefix and suffix matched")
	}
}

func TestEntraResolvedIssuer(t *testing.T) {
	t.Parallel()
	c := &Client{cfg: config{tenantIssuer: true}}
	const guid = "9188040d-6c67-4c5b-b112-36a304b66dad"
	for _, tc := range []struct {
		configured, doc string
		ok              bool
	}{
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + guid + "/v2.0", true},
		{"https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0", "https://login.microsoftonline.com/" + guid + "/v2.0", true},
		{"https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0", "https://login.microsoftonline.com/" + strings.ToUpper(guid) + "/v2.0", true},
		// Only a name may resolve, only to a GUID, and only in the tenant segment.
		{"https://login.microsoftonline.com/" + guid + "/v2.0", "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/other/v2.0", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://evil.example/" + guid + "/v2.0", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "http://login.microsoftonline.com/" + guid + "/v2.0", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + guid + "/v1.0", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + guid + "/v2.0/x", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + guid + "/v2.0?x=1", false},
		{"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + guid[:35] + "g/v2.0", false},
		{"https://login.microsoftonline.com", "https://login.microsoftonline.com/" + guid, false},
		{"%zz", "https://login.microsoftonline.com/" + guid + "/v2.0", false},
	} {
		if got := c.entraResolvedIssuer(tc.configured, tc.doc); got != tc.ok {
			t.Errorf("entraResolvedIssuer(%q, %q) = %v, want %v", tc.configured, tc.doc, got, tc.ok)
		}
	}
	if (&Client{}).entraResolvedIssuer("https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/"+guid+"/v2.0") {
		t.Fatal("resolved issuer accepted without the Entra preset")
	}
}

func TestPostsNeverFollowRedirects(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	stolen := 0
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { stolen++ }))
	defer evil.Close()
	as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	})
	env := newTestEnv(t, as, WithClientSecret("s3cret"), WithFlow(FlowClientCredentials))
	_, err := env.client.ClientCredentials(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want a refused redirect", err)
	}
	if stolen != 0 {
		t.Fatal("the token request was replayed to the redirect target")
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"`))
		chunk := []byte(strings.Repeat("a", 64<<10))
		for range (maxBodySize / len(chunk)) + 2 {
			_, _ = w.Write(chunk)
		}
	})
	env := newTestEnv(t, as, WithClientSecret("s"))
	if _, err := env.client.ClientCredentials(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}
