# Provider notes

cobra-oauth2 is provider-agnostic: give it an issuer and a client ID and it
discovers the rest. Real providers differ in small ways, though. Some have no
discovery document, some want a secret that is not secret, and some send
errors with a 200 status. This page lists, per provider, which flows work,
what to register and configure, and which quirks the library already handles.

Each preset is an `auth.Option` that sets only what differs for its provider:
the issuer or static endpoints, how the client authenticates, default scopes,
and the narrow issuer exceptions a few providers need. Put the preset first,
because options after it override what it set:

```go
auth.NewAuthCommand(
	auth.Okta("https://example.okta.com/oauth2/default"),
	auth.WithClientID("0oa..."),
	auth.WithScopes("openid", "offline_access", "api:read"),
)
```

Provider behaviour changes. The notes below reflect each provider's documented
behaviour at the time of writing. When a provider changes, override the
affected option rather than waiting for a new preset, and please
[open an issue](https://github.com/nauthera/cobra-oauth2/issues) so the
preset can follow.

## Handled for every provider

The library tolerates the common deviations without any configuration:

- Sends `Accept: application/json` and still parses form-encoded responses
  (GitHub).
- Treats a body with an `error` member as an error whatever the HTTP status:
  200 (GitHub), 400, 401, 403 (Auth0, Google), 428 (Google) or 429.
- Accepts numbers sent as strings (`"expires_in": "3599"`, from Entra v1 and
  ADFS).
- Treats a missing `expires_in` as a non-expiring token. It still refreshes
  on a `401 invalid_token` when there is a refresh token.
- Compares `token_type` case-insensitively (`bearer`, `Bearer`, `DPoP`), and
  treats a missing one as Bearer.
- Accepts `verification_url` as well as `verification_uri` in the device flow
  (Google, Entra v1).
- Accepts a comma-separated `scope` (GitHub). A missing `scope` means the
  requested scope was granted.
- Keeps the old refresh token when a refresh response has none (Google,
  Cognito).
- Keeps unknown token-response members in `Token.Extra` (`ext_expires_in`,
  `refresh_expires_in`, `session_state` and so on). They are not stored.
- On `slow_down`, uses the server's new `interval` when it sends one
  (GitHub), and adds 5 s otherwise.
- Treats unknown device-flow error codes, such as `incorrect_device_code` or
  `device_flow_disabled`, as final.
- Does not require `code_challenge_methods_supported` in discovery. PKCE S256
  is sent regardless (Entra and Google do not advertise it).

## At a glance

| Provider | Preset | Browser | Device | Refresh | Revocation | ID tokens | DPoP | PAR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nauthera-server | `Nauthera(issuer)` | yes | yes | rotating | yes | yes | yes | yes |
| GitHub | `GitHub()`, `GitHubEnterprise(host)` | yes | opt-in per app | GitHub Apps only | no | no | no | no |
| Google | `Google()` | yes | TV and limited-input clients | not rotated | yes | yes | no | no |
| Microsoft Entra ID | `EntraID(tenant)` | yes | allow public client flows | rotating | no | yes | no | no |
| Okta | `Okta(issuer)` | yes | enable the grant | rotating | yes | yes | yes (nonce) | yes |
| Auth0 | `Auth0(domain, audience)` | yes | enable the grant | rotating | refresh tokens | yes | plan-dependent | plan-dependent |
| Keycloak | `Keycloak(baseURL, realm)` | yes | enable the grant | realm setting | yes | yes | 24+ | yes |
| GitLab | `GitLab(baseURL)` | yes | 17.1+ | rotating | yes | yes | no | no |
| ZITADEL | `Zitadel(issuer)` | yes | yes | rotating | yes | yes | no | no |
| Amazon Cognito | `Cognito(region, pool, domain)` | fixed port | no | optional rotation | yes (if enabled) | yes | no | no |
| Dex | `Dex(issuer)` | yes | yes | rotating | no | yes | no | no |

"PAR" means pushed authorization requests. The library uses them
automatically whenever a server requires them, and on request otherwise.
"DPoP" only matters when you enable it with `WithDPoP` or `WithDPoPAuto`.

---

## nauthera-server

```go
auth.Nauthera("https://auth.example.com") // tenant: https://auth.example.com/orgs/acme
```

This is the reference server. Register a public client with the
authorization code and device grants, the loopback redirect
`http://127.0.0.1/callback` (any port matches) and `offline_access`. The
preset requests `openid offline_access`. DPoP, PAR, resource indicators and
private_key_jwt are all supported. See [nauthera.md](nauthera.md) for the
details.

## GitHub

```go
auth.GitHub()                              // github.com
auth.GitHubEnterprise("github.example.com") // GitHub Enterprise Server
```

- **Flows:** the device flow (enable "Device Flow" in the app's settings) and
  the browser flow. GitHub accepts any port on a registered
  `http://127.0.0.1/...` callback and supports PKCE.
- **Setup:** use the client ID of a GitHub App or OAuth App. Scopes are
  GitHub's own (`repo`, `read:org`, `read:user`), and the preset requests none
  by default. A GitHub App's permissions come from the app, not from scopes.
- **What the preset does:** GitHub has no discovery document, so the preset
  sets static endpoints (`/login/oauth/authorize`,
  `/login/oauth/access_token`, `/login/device/code`). It sends a client
  secret, if you set one, in the request body, and sends only the client ID
  to the device endpoint.
- **Quirks handled:** form-encoded responses, device-flow errors with HTTP
  200, `slow_down` with a new `interval`, lowercase `bearer`, comma-separated
  scopes, and no `expires_in` from OAuth Apps.
- **Limits:** no ID tokens, so `status` shows no account name. There is no
  RFC 7009 revocation, so logout only deletes the local tokens. Revoke from
  GitHub's settings, or call its REST API from your own code. Only GitHub
  Apps with expiring tokens get a refresh token, and that refresh needs the
  app's client secret.

## Google

```go
auth.Google(), auth.WithClientSecret("GOCSPX-...") // the installed-app "secret"
```

- **Flows:** the browser flow with a "Desktop app" client, and the device flow
  with a "TVs and Limited Input devices" client. The device flow allows only
  a limited set of scopes.
- **Setup:** Google issues these client types a secret that is not
  confidential but is still required. Pass it with `WithClientSecret`, and
  treat it as public. The preset sends it in the body, and only to the token
  endpoint.
- **What the preset does:** discovers from `https://accounts.google.com`,
  requests `openid email profile`, and accepts both of Google's issuer
  spellings in ID tokens (`https://accounts.google.com` and
  `accounts.google.com`). JWT client assertions use the token endpoint as
  their audience.
- **Refresh tokens:** Google decides whether to issue one. For the browser
  flow you may need `WithAuthParam("access_type", "offline")` and
  `WithAuthParam("prompt", "consent")`. Refresh tokens are not rotated.
- **Quirks handled:** `verification_url`, `authorization_pending` as HTTP 428
  and `slow_down` as 403. Loopback on `127.0.0.1` with any port works.

## Microsoft Entra ID

```go
auth.EntraID("organizations") // or a tenant ID, a verified domain, "common", "consumers"
```

- **Flows:** browser and device. For the device flow, enable "Allow public
  client flows" on the app registration.
- **Setup:** register the redirect `http://localhost` under "Mobile and
  desktop applications". Entra ignores the port for loopback hosts, and
  `127.0.0.1` works too. **Do not configure a secret** for a public client:
  Entra rejects a public client that sends one (AADSTS700025).
- **Scopes:** Entra scopes are resource-qualified, such as
  `api://<app-id>/access` or `https://graph.microsoft.com/.default`, and one
  token covers one resource. The preset requests
  `openid profile offline_access`. Add your API's scope with `WithScopes`,
  keeping `offline_access`, which Entra needs before it issues a refresh
  token. For several APIs, use one client configuration per API. Tokens are
  stored per audience and resource, so they do not collide.
- **What the preset does:** for `common` and `organizations` the discovery
  document names the issuer with a literal `{tenantid}` placeholder. The
  preset accepts that document, and checks each ID token's `iss` against the
  template filled in with the token's own `tid` claim. For `consumers` and
  for a verified domain (`contoso.onmicrosoft.com`), the document names the
  tenant's GUID instead of the name you configured
  (`https://login.microsoftonline.com/<tenant-guid>/v2.0`; for `consumers`
  the GUID is `9188040d-6c67-4c5b-b112-36a304b66dad`). The preset accepts
  exactly that: the same host and path with the tenant segment replaced by a
  GUID. The document's issuer is then the one ID tokens and the RFC 9207
  `iss` parameter are compared with, while tokens stay stored under the
  issuer you configured. Other issuer mismatches are still refused. JWT
  client assertions use the token endpoint as their audience.
- **Limits:** no RFC 7009 revocation, so logout is local. Use
  `WithEndSession` to also end the browser session. `ext_expires_in` and
  `refresh_token_expires_in` land in `Token.Extra`.

## Okta

```go
auth.Okta("https://example.okta.com/oauth2/default") // custom server; org server: https://example.okta.com
```

- **Flows:** browser and device. Create a native app with client
  authentication `none`, and enable the Device Authorization grant if you
  want it. Register the loopback redirect URI. Okta matches the port unless
  you register the URI without one, so set `WithRedirectPort` if needed.
- **What the preset does:** requests `openid profile offline_access` and uses
  the token endpoint as the client-assertion audience.
- **DPoP:** Okta supports it and always asks for a nonce first. The library
  answers that with one retry. Enable it with `WithDPoPAuto()` or `WithDPoP()`.
- The org server and custom servers have different issuers. Configure the
  one your app uses, because the library compares it exactly.

## Auth0

```go
auth.Auth0("example.eu.auth0.com", "https://api.example.com") // domain, API audience
```

- **Flows:** browser and device. Create a "Native" application, enable the
  Device Code grant if you want it, and add `http://127.0.0.1:<port>/callback`
  to Allowed Callback URLs with a fixed `WithRedirectPort`, since Auth0
  matches the port.
- **Audience:** without an `audience` Auth0 issues an opaque token that only
  works at `/userinfo`. Pass your API's identifier as the second argument
  (`WithAudience` does the same). Tokens are stored per audience.
- **What the preset does:** keeps the trailing slash in the issuer
  (`https://example.eu.auth0.com/`), because Auth0 publishes it that way and
  the issuer check is exact. Requests `openid profile offline_access`.
- **Quirks handled:** device-flow errors with 403 and 429. Refresh token
  rotation with reuse detection. The revocation endpoint revokes refresh
  tokens only. PAR, JAR and DPoP depend on your plan; the library follows the
  discovery flags.
- **Example:** [examples/auth0](../examples/auth0) sets up the Auth0
  applications step by step; the live tests in `e2e/auth0_e2e_test.go` run
  against a real tenant.

## Keycloak

```go
auth.Keycloak("https://sso.example.com", "myrealm") // Keycloak < 17: "https://sso.example.com/auth"
```

- **Flows:** browser and device. Enable "OAuth 2.0 Device Authorization
  Grant" on the client if you want the device flow. Make the client public
  ("Client authentication" off).
- **Redirects:** recent versions accept loopback with any port for public
  clients. Older ones need a wildcard such as `http://127.0.0.1:*/callback`
  or `http://127.0.0.1/*`.
- **What the preset does:** requests `openid profile`, and deliberately not
  `offline_access`. In Keycloak that scope asks for an *offline* token, which
  has different session semantics. A normal refresh token is issued without
  it.
- **Notes:** refresh-token rotation is a realm setting. DPoP is advertised
  from Keycloak 24. Token exchange is available to confidential clients in
  recent versions. Access tokens often have `aud: account`; that is fine,
  because the library never validates access tokens.

## GitLab

```go
auth.GitLab("https://gitlab.com") // or a self-managed instance
```

- **Flows:** browser, and device from GitLab 17.1. Untick "Confidential"
  for a public application.
- **What the preset does:** GitLab may not advertise the device endpoint in
  discovery, so the preset fills in `/oauth/authorize_device` when it is
  missing. It requests `openid profile`. GitLab always issues refresh tokens
  and has no `offline_access` scope.
- **Redirects** are matched exactly. Check how your instance treats ports, or
  prefer the device flow.
- Access tokens last about 2 hours, and refresh tokens rotate. `created_at`
  lands in `Token.Extra`.

## ZITADEL

```go
auth.Zitadel("https://example.zitadel.cloud")
```

- **Flows:** browser and device. Use a native application with
  authentication method `none` (PKCE). `http://localhost` and loopback
  redirects need "Development mode" on the application.
- **Scopes:** ZITADEL's reserved scopes contain colons and are passed through
  as they are, for example
  `WithScopes("openid", "offline_access", "urn:zitadel:iam:org:project:id:<id>:aud")`.
  The preset requests `openid profile offline_access`.
- Introspection requires an API application with private_key_jwt or Basic.
  Use `Client.Introspect` only from such a confidential client.

## Amazon Cognito

```go
auth.Cognito("eu-west-1", "eu-west-1_AbCdEf123", "example.auth.eu-west-1.amazoncognito.com"),
auth.WithRedirectPort(53682),
```

- **Flows:** browser only. Cognito has no device authorization grant, so the
  preset sets the flow to `FlowBrowser`.
- **Redirects:** Cognito matches callback URLs exactly, **port included**,
  and allows plain http only for `localhost`. Register
  `http://localhost:<port>/callback` and set the same port with
  `WithRedirectPort`. The preset switches the redirect host to `localhost`.
  `NewClient` refuses a Cognito browser configuration without a fixed port
  with `ErrInvalidConfig`, rather than letting every login fail at Cognito.
- **What the preset does:** discovery comes from the `cognito-idp` issuer,
  while the authorize, token and revoke endpoints live on the hosted UI
  domain you pass. The preset fills those in when the metadata lacks them.
  It requests `openid profile`.
- **Notes:** an app client with a secret uses HTTP Basic. Refresh responses
  omit `refresh_token` unless rotation is enabled, and the library keeps the
  old one. Revocation works only when token revocation is enabled on the app
  client.

## Dex

```go
auth.Dex("https://dex.example.com")
```

- **Flows:** browser and device. For the device flow, the client's redirect
  URIs on the server must include `/device/callback`. Public clients
  (`public: true`) accept loopback with any port.
- **What the preset does:** requests `openid profile offline_access`.
- Dex has **no revocation endpoint**, so logout deletes the local tokens only.

## Any other server

Any server that publishes OpenID Connect Discovery or RFC 8414 metadata works
with `WithIssuer` alone. For a server without discovery, give the endpoints:

```go
auth.WithIssuer("https://legacy.example.com"), // names the server in storage
auth.WithoutDiscovery(),
auth.WithEndpoints(auth.Endpoints{
	Authorization:       "https://legacy.example.com/oauth/authorize",
	Token:               "https://legacy.example.com/oauth/token",
	DeviceAuthorization: "https://legacy.example.com/oauth/device",
	Revocation:          "https://legacy.example.com/oauth/revoke",
}),
auth.WithIDTokenValidation(false), // only if it issues ID tokens without a JWKS
```

Useful knobs for unusual servers:

- `WithAuthParam` and `WithTokenParam` add vendor parameters.
- `WithAuthMethod(auth.ClientAuthSecretPost)` puts the secret in the body.
- `WithRedirectHost` and `WithRedirectPort` fit strict redirect matching.
- `WithDiscoveryURL` reads metadata published in a non-standard place.
- `WithEndpointMiddleware` inspects or adjusts back-channel requests.

If you find a quirk the library should tolerate, a fixture test is the
preferred way to capture it. See [CONTRIBUTING.md](../CONTRIBUTING.md).
