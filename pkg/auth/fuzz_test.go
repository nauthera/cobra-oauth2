package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// The fuzz targets below cover every parser that reads server-controlled
// or browser-controlled input. Each run of `go test` replays the seeds;
// `go test -fuzz=FuzzX ./pkg/auth` explores further.

// assertPrintable fails when s holds a character sanitize must remove.
func assertPrintable(t *testing.T, what, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s is not valid UTF-8: %q", what, s)
	}
	for _, r := range s {
		if isUnsafeRune(r) {
			t.Fatalf("%s contains unsafe rune %U: %q", what, r, s)
		}
	}
}

func FuzzDecodeTokenResponse(f *testing.F) {
	seeds := []struct {
		status int
		ct     string
		body   string
	}{
		{200, "application/json", `{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r","scope":"openid"}`},
		{200, "application/json", `{"access_token":"a","token_type":"bearer","expires_in":"3599","ext_expires_in":"3599"}`},
		{200, "application/x-www-form-urlencoded", "access_token=a&token_type=bearer&scope=repo%2Cgist"},
		{200, "text/plain", "error=authorization_pending&error_description=pending"},
		{200, "application/json", `{"error":"slow_down","interval":10}`},
		{400, "application/json", `{"error":"invalid_grant","error_description":"\u001b[31mred\u202e","error_uri":"https://x"}`},
		{428, "application/json", `{"error":"authorization_pending"}`},
		{503, "text/html", "<html>busy</html>"},
		{200, "application/json", `{"access_token":"a","token_type":"mac"}`},
		{200, "application/json", `{"access_token":"a","expires_in":1e309}`},
		{200, "application/json", `{"access_token":"a","expires_in":-5,"scope":7}`},
		{200, "application/json", `{"access_token":`},
		{200, "", ""},
	}
	for _, s := range seeds {
		f.Add(s.status, s.ct, []byte(s.body))
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, status int, ct string, body []byte) {
		resp := &EndpointResponse{StatusCode: status, Header: http.Header{"Content-Type": {ct}}, Body: body}
		tok, err := decodeTokenResponse(resp, now, "requested")
		if err != nil {
			var oe *OAuthError
			if errors.As(err, &oe) {
				assertPrintable(t, "error code", oe.Code)
				assertPrintable(t, "error description", oe.Description)
				assertPrintable(t, "error URI", oe.URI)
				// Code may be empty when the server's error member held only
				// characters sanitize removes; it is still an error.
				if utf8.RuneCountInString(oe.Code) > maxCodeLen+1 || utf8.RuneCountInString(oe.Description) > maxDescriptionLen+1 {
					t.Fatalf("bad OAuthError: %+v", oe)
				}
			}
			if tok != nil {
				t.Fatal("token returned with an error")
			}
			return
		}
		if status < 200 || status > 299 {
			t.Fatalf("status %d accepted as success", status)
		}
		if tok.AccessToken == "" || (tok.TokenType != TokenTypeBearer && tok.TokenType != TokenTypeDPoP) {
			t.Fatalf("accepted an unusable token: %+v", tok)
		}
		if !tok.Expiry.IsZero() && !tok.Expiry.After(now) {
			t.Fatalf("expiry %v not after now", tok.Expiry)
		}
		if strings.Contains(tok.Scope, ",") {
			t.Fatalf("scope not normalized: %q", tok.Scope)
		}
	})
}

func FuzzParseDeviceAuthorization(f *testing.F) {
	f.Add([]byte(`{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://as.example/device","verification_uri_complete":"https://as.example/device?c=1","expires_in":900,"interval":5}`))
	f.Add([]byte(`{"device_code":"d","user_code":"A","verification_url":"https://as.example/device","expires_in":"1800","interval":"5"}`))
	f.Add([]byte(`{"device_code":"d","user_code":"\u001b]8;;","verification_uri":"https://as.example"}`))
	f.Add([]byte(`{"device_code":"d","user_code":"A","verification_uri":"javascript:alert(1)"}`))
	f.Add([]byte(`{"device_code":"d","user_code":"A","verification_uri":"http://evil.example/"}`))
	f.Add([]byte(`{"device_code":"d","user_code":"A","verification_uri":"https://u:p@as.example/"}`))
	f.Add([]byte(`{"device_code":"d","user_code":"A","verification_uri":"https://as.example/","expires_in":99999999,"interval":0}`))
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		fields, err := parseFields(&EndpointResponse{StatusCode: 200, Header: http.Header{}, Body: body})
		if err != nil {
			return
		}
		da, err := c.parseDeviceAuthorization(fields, "openid")
		if err != nil {
			return
		}
		if !validUserCode(da.UserCode) {
			t.Fatalf("unsafe user code accepted: %q", da.UserCode)
		}
		for _, raw := range []string{da.VerificationURI, da.VerificationURIComplete} {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
				t.Fatalf("unsafe verification URI accepted: %q", raw)
			}
			assertPrintable(t, "verification URI", raw)
		}
		if da.Interval <= 0 || da.Interval > maxDeviceTTL {
			t.Fatalf("interval %v out of bounds", da.Interval)
		}
		if ttl := time.Until(da.ExpiresAt); ttl > maxDeviceTTL+time.Minute {
			t.Fatalf("expiry %v beyond the bound", ttl)
		}
	})
}

func FuzzDiscoveryDocument(f *testing.F) {
	f.Add("https://as.example", []byte(`{"issuer":"https://as.example","token_endpoint":"https://as.example/token"}`))
	f.Add("https://as.example/orgs/acme", []byte(`{"issuer":"https://as.example/orgs/acme","token_endpoint":"http://as.example/token"}`))
	f.Add("https://login.example/common/v2.0", []byte(`{"issuer":"https://login.example/{tenantid}/v2.0","token_endpoint":"https://login.example/t"}`))
	f.Add("https://as.example/", []byte(`{"issuer":"https://as.example/","device_authorization_endpoint":"file:///etc/passwd"}`))
	f.Add("https://as.example?x=1", []byte(`[]`))
	// Prefix and suffix of the template overlap inside the issuer.
	f.Add("https://login.microsoftonline.com/v2.0", []byte(`{"issuer":"https://login.microsoftonline.com/{tenantid}/v2.0"}`))
	f.Add("https://login.microsoftonline.com/consumers/v2.0",
		[]byte(`{"issuer":"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"}`))
	f.Fuzz(func(t *testing.T, issuer string, body []byte) {
		if urls, err := MetadataURLs(issuer); err == nil {
			// For a plain issuer, each metadata URL leads back to it.
			pu, perr := url.Parse(issuer)
			plain := perr == nil && pu.Scheme == "https" && pu.Host != "" && pu.Opaque == "" && pu.User == nil &&
				pu.String() == issuer && !strings.Contains(issuer, ".well-known")
			for _, u := range urls {
				if !strings.Contains(u, "/.well-known/") {
					t.Fatalf("metadata URL %q has no well-known segment", u)
				}
				if back, err := issuerFromDiscoveryURL(u); plain && (err != nil || back != strings.TrimSuffix(issuer, "/")) {
					t.Fatalf("round trip %q -> %q -> %q (%v)", issuer, u, back, err)
				}
			}
		}
		var md Metadata
		if json.Unmarshal(body, &md) != nil {
			return
		}
		c := &Client{cfg: defaultConfig()}
		if err := c.validateMetadataEndpoints(&md); err != nil {
			return
		}
		for _, ep := range []string{md.TokenEndpoint, md.AuthorizationEndpoint, md.DeviceAuthorizationEndpoint, md.RevocationEndpoint} {
			if ep == "" {
				continue
			}
			u, err := url.Parse(ep)
			if err != nil || (u.Scheme != "https" && !isLoopbackHost(u.Hostname())) {
				t.Fatalf("insecure endpoint accepted: %q", ep)
			}
		}
		c.cfg.tenantIssuer = true
		if c.issuerMatches(issuer, md.Issuer) && md.Issuer != issuer && !strings.Contains(md.Issuer, "{tenantid}") {
			t.Fatalf("issuer %q matched %q", md.Issuer, issuer)
		}
		// The Entra name-to-GUID exception changes one path segment, nothing else.
		if c.entraResolvedIssuer(issuer, md.Issuer) {
			cu, _ := url.Parse(issuer)
			du, _ := url.Parse(md.Issuer)
			if cu == nil || du == nil || cu.Host != du.Host || cu.Scheme != du.Scheme {
				t.Fatalf("resolved issuer %q for %q changes the origin", md.Issuer, issuer)
			}
		}
	})
}

func FuzzCallback(f *testing.F) {
	const state = "expected-state-0123456789abcdefghijklmnopqrstu"
	f.Add("code=c&state=" + state + "&iss=https%3A%2F%2Fas.example")
	f.Add("code=c&state=" + state)
	f.Add("error=access_denied&error_description=%1B%5B2J&state=" + state + "&iss=https%3A%2F%2Fas.example")
	f.Add("code=c&state=wrong&iss=https%3A%2F%2Fas.example")
	f.Add("code=c&state=" + state + "&iss=https%3A%2F%2Fevil.example")
	f.Add("code=c&state=" + state + "&iss=a&iss=b")
	f.Add("state=" + state + "&iss=https%3A%2F%2Fas.example")
	f.Add("%zz")
	c, err := NewClient(WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, rawQuery string) {
		for _, issParam := range []bool{false, true} {
			md := &Metadata{Issuer: "https://as.example", AuthorizationResponseIssParameterSupported: issParam}
			results := make(chan callbackResult, 1)
			h := c.callbackHandler(md, state, results)
			req := httptest.NewRequest(http.MethodGet, "/callback", http.NoBody)
			req.URL.RawQuery = rawQuery
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("callback page is cacheable")
			}
			q, _ := url.ParseQuery(rawQuery)
			select {
			case res := <-results:
				if q.Get("state") != state {
					t.Fatalf("a callback with state %q was accepted", q.Get("state"))
				}
				if res.err == nil {
					if res.code == "" || q.Get("error") != "" {
						t.Fatalf("bad success: %+v for %q", res, rawQuery)
					}
					if iss, ok := q["iss"]; (ok && (len(iss) != 1 || iss[0] != md.Issuer)) || (issParam && !ok) {
						t.Fatalf("iss check bypassed for %q", rawQuery)
					}
					if rec.Code != http.StatusOK {
						t.Fatalf("success page status %d", rec.Code)
					}
				} else {
					assertPrintable(t, "callback error", res.err.Error())
				}
			default:
				if q.Get("state") == state {
					t.Fatalf("a callback with the right state produced no result: %q", rawQuery)
				}
			}
		}
	})
}

func FuzzParseChallenges(f *testing.F) {
	for _, s := range []string{
		`Bearer realm="api", error="invalid_token", error_description="expired"`,
		`DPoP error="use_dpop_nonce", algs="ES256 PS256"`,
		`Bearer realm="x", DPoP algs="ES256", error="use_dpop_nonce"`,
		`Basic dXNlcjpwYXNz==, Bearer error=invalid_token`,
		`Bearer error="a\"b\\c`,
		`,,,  ,`,
		`=`,
		`Bearer a=b, , c=d`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		chs := parseChallenges([]string{header})
		if len(chs) > len(header) {
			t.Fatalf("%d challenges from %d bytes", len(chs), len(header))
		}
		for _, ch := range chs {
			if ch.scheme == "" || ch.scheme != strings.ToLower(ch.scheme) {
				t.Fatalf("bad scheme %q", ch.scheme)
			}
		}
		_ = hasChallengeError(http.Header{"Www-Authenticate": {header}}, "invalid_token")
	})
}

func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"plain", "\x1b[31mred\x1b[0m", "a\u202eb\u2066c", "\xff\xfe", strings.Repeat("é", 400), "line\nbreak\r\x00"} {
		f.Add(s, 10)
	}
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 1000 {
			return
		}
		out := sanitize(s, n)
		assertPrintable(t, "sanitize output", out)
		if utf8.RuneCountInString(out) > n+1 {
			t.Fatalf("sanitize(%q, %d) has %d runes", s, n, utf8.RuneCountInString(out))
		}
	})
}

func FuzzIntrospection(f *testing.F) {
	f.Add([]byte(`{"active":true,"scope":"a b","client_id":"c","exp":1900000000,"aud":["x","y"]}`))
	f.Add([]byte(`{"active":"true","exp":"1900000000","aud":"x"}`))
	f.Add([]byte(`{"active":false}`))
	f.Add([]byte(`{"active":1}`))
	f.Add([]byte(`{"exp":99999999999}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fields, err := parseFields(&EndpointResponse{StatusCode: 200, Header: http.Header{}, Body: body})
		if err != nil || fields == nil {
			return
		}
		in, err := parseIntrospection(fields)
		if err != nil {
			return
		}
		if !in.Active && (in.Scope != "" || in.ClientID != "" || !in.Expiry.IsZero()) {
			t.Fatalf("an inactive token reported details: %+v", in)
		}
	})
}
