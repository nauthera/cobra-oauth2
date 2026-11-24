# Live tests against nauthera-server

The tests in this directory run the library against a real authorization
server. They are behind the `e2e` build tag, so `just test` and CI never run
them, and they skip unless the environment names a server and a client.

The unit suite already replays nauthera-server's responses from fixtures
(`pkg/auth/testdata/nauthera`). These tests are the check that the fixtures
still match a running server, and the place to try a flow end to end before
a release or after the server changed.

## What you need

- A running nauthera-server reachable over **https**. Its own CONTRIBUTING.md
  is the reference for running one; the outline below is only a guide, and
  the server's details (ports, config keys, CLI flags) may have moved on.
- A **public client** on it with the device grant. Add the authorization code
  grant and the loopback redirect URI `http://127.0.0.1/callback` if you also
  want to try the browser flow by hand.
- Optionally a **confidential client** with the client credentials grant, for
  the client credentials and introspection tests.
- Optionally a **test user** with a password, a verified address and no
  second factor, so the tests can approve and deny device codes without a
  person. Create it however the server lets you (self-service registration
  when it is enabled, an invitation, or the admin interface). Use a user that
  exists only for testing: the tests sign in as it.

## Getting a server

Pick whichever is closest to what you have:

- **A server you already run** (staging, a colleague's machine): use its
  issuer and register the clients there.
- **A local build from a nauthera-server checkout**: start its database, run
  the server with TLS and an `https://127.0.0.1:<port>` issuer, and wait for
  its readiness endpoint. The server's `config.e2e.yaml` and its own e2e
  helpers show a working set of settings; self-signed certificates are fine
  (see below). Build the binaries into a directory of your own rather than
  into the checkout if you want to keep it clean.
- **The container image**: it serves the API, but client registration goes
  through the server's admin interface or CLI, which may not be in the image;
  register the client from a local build of the CLI.

Registering the public client looks roughly like this with the server's CLI
(check `nauthera-cli create client --help` for the current flags):

```bash
nauthera-cli create client my-cli-e2e --public \
  --redirect-uri http://127.0.0.1/callback \
  --grant-types authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code \
  --scopes openid,profile,email,offline_access
```

nauthera issues a refresh token only when the client may refresh and the
granted scope contains `offline_access`, which the tests request by default.

## Running

```bash
export NAUTHERA_E2E_ISSUER=https://127.0.0.1:8443      # exactly as the server's discovery names it
export NAUTHERA_E2E_CLIENT_ID=my-cli-e2e
just e2e                                              # or: go test -tags e2e -count=1 -v ./e2e/...
```

Arguments pass through to `go test`: `just e2e -run TestDevice`.

| Variable | Effect |
|---|---|
| `NAUTHERA_E2E_ISSUER` | Issuer URL. Required. Compared byte for byte with the discovery document. |
| `NAUTHERA_E2E_CLIENT_ID` | The public client. Required. |
| `NAUTHERA_E2E_SCOPES` | Scopes, comma- or space-separated. Default `openid offline_access`. |
| `NAUTHERA_E2E_CLIENT_SECRET` | Secret of a confidential client; enables the client credentials tests. |
| `NAUTHERA_E2E_SERVICE_CLIENT_ID` | That confidential client's ID. Defaults to `NAUTHERA_E2E_CLIENT_ID`. |
| `NAUTHERA_E2E_CA_FILE` | PEM bundle to trust besides the system roots. |
| `NAUTHERA_E2E_USER_EMAIL`, `NAUTHERA_E2E_USER_PASSWORD` | A test user; enables the automated approval and denial tests. |
| `NAUTHERA_E2E_INTERACTIVE=1` | Runs the full device login; approve the printed code in a browser within ten minutes. |
| `NAUTHERA_E2E_DPOP=1` | Uses DPoP in the interactive login. |

A `.env` file is git-ignored if you want to keep the settings around.

### What runs without a person

- Discovery: exact issuer match, https endpoints, S256, the device grant and
  RFC 9207 `iss` are advertised; a document fetched for a different issuer
  string is refused.
- The device flow up to the first poll, which must answer
  `authorization_pending`, with and without DPoP (the DPoP variant also
  exercises `dpop_jkt` and the server's nonce round trip).
- Token exchange is refused before any request when it is not advertised.
- With a confidential client: client credentials with `client_secret_basic`,
  introspection, revocation, and refusal of a wrong secret.

### What runs with a test user

With `NAUTHERA_E2E_USER_EMAIL` and `NAUTHERA_E2E_USER_PASSWORD` set, the
tests act for that user through the server's hosted sign-in API: they sign in
with the password (keeping the session cookie, as a browser would), then
approve or deny the device code from a `DeviceAuthorizationHandler`, so the
library's poll finds the decision.

- `TestAutomatedDeviceLogin`: approval, a DPoP-bound token when the server
  advertises DPoP, a userinfo call through `Client.Transport`, refresh with
  rotation, reuse of the spent refresh token refused (and the newer one
  revoked with it), and a second login whose refresh token stops working
  after logout.
- `TestAutomatedDeviceDenial`: a denied code ends the poll with
  `access_denied`, and nothing is stored.

The sign-in and decision endpoints (`/v1/auth/sign-in`,
`/v1/auth/device/decision` below the issuer) are nauthera's own, not a
standard, and the only place the tests depend on the server's internals. If
they move, adapt `hostedUser` in the test file; the library is not involved.

### What needs a person

With `NAUTHERA_E2E_INTERACTIVE=1` the test prints a code and URL on stderr and
waits for approval, then calls userinfo through `Client.Transport`, refreshes,
checks that reusing the spent refresh token is refused, and logs out. Run it
with `-run TestInteractiveDeviceLogin -v` so the prompt is visible.

## In CI

`.github/workflows/e2e.yml` runs these tests on every push to `main` and on
demand (Actions → e2e → Run workflow), never on pull requests. It targets a
dedicated organization on the hosted nauthera, declared with its two clients
in the `nauthera/gitops` repository (`apps/cobra-oauth2-e2e`). That
repository's `scripts/seal-tokens.sh cobra-oauth2-e2e` sets the Actions
variables `NAUTHERA_E2E_ISSUER`, `NAUTHERA_E2E_CLIENT_ID` and
`NAUTHERA_E2E_SERVICE_CLIENT_ID` and the secret `NAUTHERA_E2E_CLIENT_SECRET`;
re-running it rotates the secret. Without `NAUTHERA_E2E_ISSUER` the job is
skipped, so forks stay green.

The test user is optional: set `NAUTHERA_E2E_USER_EMAIL` as a variable and
`NAUTHERA_E2E_USER_PASSWORD` as a secret once a user exists in that
organization, and the automated approval tests run too.

## Auth0

`auth0_e2e_test.go` runs the same library against an Auth0 tenant, a
provider with different quirks: an issuer with a trailing slash, the
`audience` parameter and RS256 JWT access tokens. It needs a Machine to
Machine application authorized for an API
([examples/auth0/README.md](../examples/auth0/README.md) sets one up):

```bash
export AUTH0_DOMAIN=example.eu.auth0.com   # or AUTH0_DISCOVERY_URL
export AUTH0_CLIENT_ID=... AUTH0_CLIENT_SECRET=... AUTH0_AUDIENCE=https://api.example.com
go test -tags e2e -count=1 -v -run Auth0 ./e2e/...
```

It checks discovery with the exact trailing-slash issuer, client credentials
whose access token is a JWT for the audience, and that a wrong secret is
refused without being echoed. With `AUTH0_DEVICE_CLIENT_ID` (a Native
application with the Device Code grant) it also starts a device
authorization. In CI the `auth0` job of `e2e.yml` reads the repository
secrets `AUTH0_DISCOVERY_URL`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` and
`AUTH0_AUDIENCE`, and the optional variable `AUTH0_DEVICE_CLIENT_ID`.

## Certificates

A local server usually has a self-signed certificate. Trust it for the run,
never by turning TLS verification off:

```bash
NAUTHERA_E2E_CA_FILE=/path/to/ca.pem just e2e
```

`SSL_CERT_FILE` also works on Linux; on macOS Go uses the system verifier and
ignores it, so prefer `NAUTHERA_E2E_CA_FILE`.

## When a test fails

First decide which side moved. If the server changed a shape on purpose,
update the fixture under `pkg/auth/testdata/nauthera` and its README, then
adapt the library if needed. If the server no longer follows an RFC the
library relies on, raise it on the server side (CONTRIBUTING.md, "Working
alongside nauthera-server").
