package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// Token types, in their canonical spelling.
const (
	TokenTypeBearer = "Bearer"
	TokenTypeDPoP   = "DPoP"
	// TokenTypeNA is the token_type of a token from [Client.ExchangeToken]
	// that is not an access token (RFC 8693 § 2.2.1).
	TokenTypeNA = "N_A"
)

// knownTokenMembers are the token-response members modeled by
// storage.Token; everything else goes to Token.Extra.
var knownTokenMembers = map[string]bool{
	"access_token": true, "token_type": true, "refresh_token": true,
	"id_token": true, "scope": true, "expires_in": true,
}

// parseFields decodes a response body leniently: JSON objects (the RFC
// format), and application/x-www-form-urlencoded, which GitHub sends when
// the Accept header is missing or ignored. It returns nil fields for any
// other body.
func parseFields(resp *EndpointResponse) (map[string]any, error) {
	body := bytes.TrimSpace(resp.Body)
	if len(body) == 0 {
		return nil, nil
	}
	mt := ""
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		mt, _, _ = mime.ParseMediaType(ct)
	}
	switch {
	case body[0] == '{':
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var fields map[string]any
		if err := dec.Decode(&fields); err != nil {
			return nil, fmt.Errorf("decode JSON body: %w", err)
		}
		return fields, nil
	case mt == "application/x-www-form-urlencoded" || mt == "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("decode form body: %w", err)
		}
		fields := make(map[string]any, len(vals))
		for k := range vals {
			fields[k] = vals.Get(k)
		}
		return fields, nil
	default:
		return nil, nil
	}
}

// stringField returns a string member, or "" when absent or not a string.
func stringField(fields map[string]any, name string) string {
	s, _ := fields[name].(string)
	return s
}

// numberField returns a numeric member that may be encoded as a JSON
// number or a string ("3599" from Entra v1 and ADFS). ok is false when the
// member is absent or not a number.
func numberField(fields map[string]any, name string) (int64, bool) {
	var f float64
	switch v := fields[name].(type) {
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, false
		}
		f = parsed
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, false
		}
		f = parsed
	case float64:
		f = v
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > math.MaxInt32 {
		return 0, false
	}
	return int64(f), true
}

// oauthErrorFrom returns the error a response carries, if any. Per the
// providers' behavior, a non-empty error member is an error whatever the
// HTTP status (GitHub answers device polling with 200 and an error).
func oauthErrorFrom(resp *EndpointResponse, fields map[string]any) *OAuthError {
	code := stringField(fields, "error")
	if code == "" {
		return nil
	}
	return newOAuthError(resp.StatusCode, code, stringField(fields, "error_description"), stringField(fields, "error_uri"))
}

// checkResponse turns an error response into an error: an *OAuthError for
// an RFC 6749 § 5.2 body, a *StatusError otherwise. It returns the parsed
// fields of a successful response.
func checkResponse(endpoint string, resp *EndpointResponse) (map[string]any, error) {
	fields, perr := parseFields(resp)
	if oe := oauthErrorFrom(resp, fields); oe != nil {
		return nil, oe
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &StatusError{StatusCode: resp.StatusCode, Endpoint: endpoint}
	}
	if perr != nil {
		return nil, fmt.Errorf("%w: %s response: %w", ErrInvalidResponse, endpoint, perr)
	}
	return fields, nil
}

// normalizeTokenType maps the token_type member to its canonical spelling.
// The comparison is case-insensitive (GitHub sends "bearer"), and a missing
// token_type is taken as Bearer.
func normalizeTokenType(tt string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(tt)) {
	case "", "bearer":
		return TokenTypeBearer, nil
	case "dpop":
		return TokenTypeDPoP, nil
	default:
		return "", fmt.Errorf("%w: unsupported token_type %q", ErrInvalidResponse, sanitize(tt, 32))
	}
}

// normalizeScope turns a comma-separated scope (GitHub) into the RFC's
// space-separated form. The scope is server-controlled and is printed by
// the status command, so a scope token holding a control character (an
// ANSI or OSC escape sequence), a bidirectional override or invalid UTF-8
// is dropped: RFC 6749 § 3.3 allows only printable ASCII in scope tokens.
func normalizeScope(s string) string {
	sep := unicode.IsSpace
	if strings.Contains(s, ",") {
		sep = func(r rune) bool { return r == ',' || unicode.IsSpace(r) }
	}
	tokens := strings.FieldsFunc(s, sep)
	kept := tokens[:0]
	for _, t := range tokens {
		if utf8.ValidString(t) && !strings.ContainsFunc(t, isUnsafeRune) {
			kept = append(kept, t)
		}
	}
	return strings.Join(kept, " ")
}

// decodeTokenResponse parses a token endpoint response (RFC 6749 § 5.1)
// into a token set. requestedScope fills Scope when the server does not
// echo it (§ 5.1: then the granted scope equals the requested one).
func decodeTokenResponse(resp *EndpointResponse, now time.Time, requestedScope string) (*storage.Token, error) {
	fields, err := checkResponse("token", resp)
	if err != nil {
		return nil, err
	}
	return tokenFromFields(fields, now, requestedScope, false)
}

// tokenFromFields builds a token set from the members of a successful
// token response. allowNA accepts the token_type "N_A" that RFC 8693
// § 2.2.1 uses for issued tokens that are not access tokens.
func tokenFromFields(fields map[string]any, now time.Time, requestedScope string, allowNA bool) (*storage.Token, error) {
	if fields == nil {
		return nil, fmt.Errorf("%w: token response is not JSON", ErrInvalidResponse)
	}
	access := stringField(fields, "access_token")
	if access == "" {
		return nil, fmt.Errorf("%w: token response has no access_token", ErrInvalidResponse)
	}
	rawType := stringField(fields, "token_type")
	tt, err := normalizeTokenType(rawType)
	if err != nil {
		if !allowNA || !strings.EqualFold(strings.TrimSpace(rawType), TokenTypeNA) {
			return nil, err
		}
		tt = TokenTypeNA
	}
	tok := &storage.Token{
		Version:      storage.CurrentVersion,
		AccessToken:  access,
		TokenType:    tt,
		RefreshToken: stringField(fields, "refresh_token"),
		IDToken:      stringField(fields, "id_token"),
		Scope:        requestedScope,
	}
	if s, ok := fields["scope"].(string); ok {
		tok.Scope = normalizeScope(s)
	}
	if secs, ok := numberField(fields, "expires_in"); ok && secs > 0 {
		tok.Expiry = now.Add(time.Duration(secs) * time.Second)
	}
	for k, v := range fields {
		if knownTokenMembers[k] {
			continue
		}
		if tok.Extra == nil {
			tok.Extra = make(map[string]any)
		}
		tok.Extra[k] = v
	}
	return tok, nil
}
