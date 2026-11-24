package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"red \x1b[31malert\x1b[0m", "red [31malert[0m"},
		{"osc \x1b]52;c;ZXZpbA==\x07", "osc ]52;c;ZXZpbA=="},
		{"c1 \u009b31m", "c1 31m"},
		{"bidi \u202egnp.exe", "bidi gnp.exe"},
		{"new\nline\ttab\rcr\x7f", "newlinetabcr"},
		{"invalid utf8 \xff\xfe ok", "invalid utf8  ok"},
		{"arabic mark \u061cx", "arabic mark x"},
		{"line\u2028sep\u2029para", "lineseppara"},
		{"zero\u200bwidth\u2060join\ufeffbom", "zerowidthjoinbom"},
	}
	for _, tc := range cases {
		if got := sanitize(tc.in, 100); got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := sanitize(strings.Repeat("x", 20), 10); got != strings.Repeat("x", 10)+"…" {
		t.Errorf("truncation: %q", got)
	}
}

func TestValidUserCode(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{
		"WDJB-MJHT":                           true,
		"abcd 1234":                           true,
		"":                                    false,
		"BAD\x1b[2J":                          false,
		"ÄÖÜ":                                 false,
		strings.Repeat("A", maxUserCodeLen+1): false,
	} {
		if got := validUserCode(code); got != want {
			t.Errorf("validUserCode(%q) = %v, want %v", code, got, want)
		}
	}
}

func TestOAuthErrorMatchesSentinels(t *testing.T) {
	t.Parallel()
	err := error(newOAuthError(400, "access_denied", "The user said \x1b[31mno", "https://errors.example/denied"))
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatal("access_denied does not match ErrAccessDenied")
	}
	if errors.Is(err, ErrExpiredToken) {
		t.Fatal("access_denied matches ErrExpiredToken")
	}
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("error message contains an escape character: %q", err.Error())
	}
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.StatusCode != http.StatusBadRequest || oe.URI == "" {
		t.Fatalf("errors.As: %+v", oe)
	}
	if !(&OAuthError{Code: "temporarily_unavailable"}).Retryable() || (&OAuthError{Code: "invalid_grant", StatusCode: 400}).Retryable() {
		t.Fatal("Retryable classification")
	}
	if !(&OAuthError{Code: "slow_down"}).DevicePending() || (&OAuthError{Code: "access_denied"}).DevicePending() {
		t.Fatal("DevicePending classification")
	}
}

func resp(status int, contentType, body string) *EndpointResponse {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &EndpointResponse{StatusCode: status, Header: h, Body: []byte(body)}
}

func TestDecodeTokenResponse(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		resp      *EndpointResponse
		wantErr   error
		wantType  string
		wantExp   time.Duration
		wantScope string
	}{
		{
			name: "rfc", resp: resp(200, "application/json", `{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"openid email"}`),
			wantType: "Bearer", wantExp: time.Hour, wantScope: "openid email",
		},
		{
			name: "lowercase bearer, no expires_in (GitHub)", resp: resp(200, "application/json", `{"access_token":"a","token_type":"bearer","scope":"repo,read:org"}`),
			wantType: "Bearer", wantScope: "repo read:org",
		},
		{
			name: "string expires_in (Entra v1)", resp: resp(200, "application/json", `{"access_token":"a","token_type":"Bearer","expires_in":"3599"}`),
			wantType: "Bearer", wantExp: 3599 * time.Second, wantScope: "requested",
		},
		{name: "missing token_type", resp: resp(200, "application/json", `{"access_token":"a"}`), wantType: "Bearer", wantScope: "requested"},
		{name: "dpop", resp: resp(200, "application/json", `{"access_token":"a","token_type":"dpop"}`), wantType: "DPoP", wantScope: "requested"},
		{
			name: "form encoded (GitHub without Accept)", resp: resp(200, "application/x-www-form-urlencoded", `access_token=a&token_type=bearer&scope=repo`),
			wantType: "Bearer", wantScope: "repo",
		},
		{
			// A scope token carrying an escape sequence is dropped, whole.
			name: "control characters in scope", resp: resp(200, "application/json",
				`{"access_token":"a","token_type":"Bearer","scope":"read \u001b]52;c;ZXZpbA==\u0007 \u001b[2J write \u202eevil \u009b31m"}`),
			wantType: "Bearer", wantScope: "read write",
		},
		{name: "error with 200 (GitHub)", resp: resp(200, "application/json", `{"error":"authorization_pending"}`), wantErr: ErrAuthorizationPending},
		{name: "error 400", resp: resp(400, "application/json", `{"error":"invalid_grant"}`), wantErr: ErrInvalidGrant},
		{name: "error 403 (Auth0)", resp: resp(403, "application/json", `{"error":"access_denied"}`), wantErr: ErrAccessDenied},
		{name: "html 502", resp: resp(502, "text/html", `<html>bad gateway</html>`)},
		{name: "no access_token", resp: resp(200, "application/json", `{"token_type":"Bearer"}`), wantErr: ErrInvalidResponse},
		{name: "unsupported type", resp: resp(200, "application/json", `{"access_token":"a","token_type":"mac"}`), wantErr: ErrInvalidResponse},
		{name: "not json", resp: resp(200, "text/html", `<html>`), wantErr: ErrInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tok, err := decodeTokenResponse(tc.resp, now, "requested")
			if tc.name == "html 502" {
				var se *StatusError
				if !errors.As(err, &se) || se.StatusCode != http.StatusBadGateway || strings.Contains(err.Error(), "bad gateway") {
					t.Fatalf("err = %v, want a StatusError without the body", err)
				}
				return
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.TokenType != tc.wantType || tok.Scope != tc.wantScope {
				t.Fatalf("type %q scope %q, want %q %q", tok.TokenType, tok.Scope, tc.wantType, tc.wantScope)
			}
			if tc.wantExp == 0 && !tok.Expiry.IsZero() || tc.wantExp != 0 && !tok.Expiry.Equal(now.Add(tc.wantExp)) {
				t.Fatalf("expiry %v, want now+%v", tok.Expiry, tc.wantExp)
			}
		})
	}
}

func TestDecodeTokenResponseKeepsExtra(t *testing.T) {
	t.Parallel()
	tok, err := decodeTokenResponse(resp(200, "application/json",
		`{"access_token":"a","refresh_token":"r","id_token":"i","refresh_expires_in":"1800","session_state":"s"}`), time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "r" || tok.IDToken != "i" || tok.Extra["session_state"] != "s" || tok.Extra["refresh_expires_in"] != "1800" {
		t.Fatalf("token: %+v extra %v", tok, tok.Extra)
	}
	if _, ok := tok.Extra["access_token"]; ok {
		t.Fatal("known members copied to Extra")
	}
}

func TestValidateEndpoint(t *testing.T) {
	t.Parallel()
	ok := []string{"https://as.example/token", "http://127.0.0.1:8080/token", "http://localhost/x", "http://LOCALHOST./x", "http://[::1]:9/x", "https://dev.localhost/x"}
	// A *.localhost name is not loopback for back-channel requests: the
	// pure-Go resolver asks DNS for it.
	bad := []string{
		"", "http://as.example/token", "http://dev.localhost/x", "http://a.b.localhost:8080/token", "ftp://as.example", "file:///etc/passwd", "https://user:pw@as.example",
		"https://as.example/#frag", "/relative", "javascript:alert(1)", "https://",
	}
	for _, u := range ok {
		if _, err := validateEndpoint("token", u, false); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := validateEndpoint("token", u, false); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := validateEndpoint("token", "http://as.example/token", true); err != nil {
		t.Errorf("WithInsecureHTTP does not allow plain http: %v", err)
	}
	if _, err := validateEndpoint("token", "http://as.example/token", false); !errors.Is(err, ErrInsecureEndpoint) {
		t.Errorf("plain http: err = %v, want ErrInsecureEndpoint", err)
	}
}

func TestBasicCredentialsFormEncodes(t *testing.T) {
	t.Parallel()
	got, err := base64.StdEncoding.DecodeString(basicCredentials("my client:1", "p@ss w+rd/é"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "my%20client%3A1:p%40ss%20w%2Brd%2F%C3%A9" {
		t.Fatalf("credentials = %s", got)
	}
	id, secret, _ := strings.Cut(string(got), ":")
	if i, _ := url.QueryUnescape(id); i != "my client:1" {
		t.Fatalf("id does not decode back: %q", i)
	}
	if s, _ := url.QueryUnescape(secret); s != "p@ss w+rd/é" {
		t.Fatalf("secret does not decode back: %q", s)
	}
}
