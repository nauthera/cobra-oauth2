# nauthera-server fixtures

These files describe what a nauthera-server answers, so `nauthera_test.go`
can check the library against the server's real shapes without running one.
They are served by the fake authorization server in `internal/oauthtest`,
which expands the placeholders `{{issuer}}`, `{{base}}` (the issuer without a
trailing slash) and `{{origin}}` to its own URL.

Every token, code, nonce and secret is redacted. The `error_description`
texts are representative rather than verbatim: the library must never depend
on them. What the tests rely on is the shape: HTTP status, `error` code,
headers and which members are present.

| File | What it captures | Server source (nauthera-server) |
|---|---|---|
| `discovery.json` | The default document of the main organization: every endpoint below the issuer, `S256` only, ES256 ID tokens, RFC 9207 `iss`, DPoP algorithms, no token exchange in `grant_types_supported`, JWKS at `/.well-known/jwks.json` | `internal/oidcsrv/oidcsrv.go` (`Discovery`), `internal/oidcsrv/capabilities.go`, `internal/gen/publicapi` (path constants) |
| `discovery-fapi.json` | The same with `require_pushed_authorization_requests: true`, as an organization in FAPI mode or with `fapi.require_pushed_authorization_requests` publishes it | `internal/oidcsrv/oidcsrv.go` (`caps.RequirePAR`) |
| `responses/device-authorization.json` | A device authorization response: `verification_uri` is `{issuer}/device`, 900 s lifetime, 5 s interval | `internal/oauthsrv/device.go`, `internal/httpapi/oauth.go` |
| `responses/token-authorization-pending.json`, `token-slow-down.json`, `token-expired-token.json`, `token-access-denied.json` | Device polling answers. All are HTTP 400 with an RFC 6749 § 5.2 body; `slow_down` lengthens the server-side interval by 5 s; an unknown, expired or used device code is `expired_token` | `internal/oauthsrv/device.go` (poll outcome mapping) |
| `responses/token-invalid-grant-reuse.json` | Reusing a rotated refresh token: plain `invalid_grant`, and the whole grant is revoked | `internal/oauthsrv/grants.go` |
| `responses/token-unauthorized-client.json` | A client not registered for the grant (the CLI default set lacks the device grant) | `internal/oauthsrv/client.go` |
| `responses/token-invalid-client.json` | Failed client authentication: 401 with `WWW-Authenticate: Basic realm="nauthera"` | `internal/httpapi/oauth.go` (`oauthError`), `internal/httpapi/server.go` |
| `responses/token-use-dpop-nonce.json` | The first DPoP proof without a nonce: 400 `use_dpop_nonce` with a `DPoP-Nonce` header (a nonce is always required at `/token`) | `internal/oauthsrv/dpop.go`, `internal/httpapi/dpop.go` |
| `responses/userinfo-use-dpop-nonce.json` | The resource-server form of the nonce challenge: 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` | `internal/httpapi/dpop.go` |
| `responses/token-exchange-unavailable.json` | Token exchange (and jwt-bearer), which the server neither serves nor advertises: 503 `temporarily_unavailable` | `internal/httpapi/oauth.go` |
| `responses/revoke-unavailable.json` | A revocation the server could not record: 503 `temporarily_unavailable`, meaning the token is still live and the client should retry | `internal/httpapi/oauth.go` (revocation handler) |

`error_uri` points at the code's runbook (`https://nauthera.io/runbooks/oauth/<code>`,
`internal/runbook/runbook.go`); the server leaves it out for a code that has
no runbook.

## Refreshing a fixture

Run a local nauthera-server (see `e2e/README.md`), fetch the document or
provoke the response with `curl -i`, **redact every token, code, nonce and
secret**, put the server's URL back as a placeholder, and commit the file with
the test change that needs it. The fixtures follow the server's main branch,
not a release; when the server changes a shape on purpose, update the fixture
and say so in the commit.
