// Package oauthtest is an in-process OAuth 2.0 and OpenID Connect
// authorization server for tests, built on net/http/httptest.
//
// A [Server] implements the parts of the protocol a command-line client
// talks to, strictly enough to catch a client that cuts corners:
//
//   - discovery at the OpenID Connect and the RFC 8414 locations, from a
//     generated document or a fixture with {{issuer}}, {{base}} and
//     {{origin}} placeholders;
//   - the authorization code grant with PKCE (S256 only), exact redirect URI
//     matching with the RFC 8252 § 7.3 loopback port exception, RFC 9207 iss
//     on the redirect, and pushed authorization requests (RFC 9126);
//   - the device authorization grant (RFC 8628), driven by a script of poll
//     outcomes (pending, slow_down, approve, deny, expire) or by
//     [Server.ApproveDevice], optionally enforcing the polling interval;
//   - refresh tokens with rotation and reuse detection that revokes the
//     whole grant, the client credentials grant, and token exchange
//     (RFC 8693), or a 503 for it as nauthera-server answers;
//   - DPoP (RFC 9449) proof verification at the token and userinfo
//     endpoints, with server nonces, jti replay detection and key binding
//     of codes, device sessions and refresh tokens;
//   - revocation (RFC 7009), introspection (RFC 7662), JWKS and ES256 ID
//     tokens.
//
// [Quirks] reproduce the deviations real providers show: errors with HTTP
// 200 or 403, form-encoded bodies, numbers as strings, verification_url,
// lower-case token types, comma-separated scopes and so on.
//
// The server never calls t.Fatal from a handler; protocol violations are
// answered with OAuth errors, the way a real server would, and the test
// sees them through the client under test.
package oauthtest
