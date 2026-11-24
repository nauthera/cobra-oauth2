# Auth0 example

A CLI that signs in to [Auth0](https://auth0.com) with cobra-oauth2 and calls
your API with the access token. It uses the `auth.Auth0` preset, which keeps
the trailing slash in the issuer that Auth0 publishes, sends the `audience`
parameter and asks for `offline_access`, so a refresh token keeps the CLI
signed in.

```text
auth0-example auth login     # browser, or the device flow over SSH
auth0-example auth status
auth0-example auth token     # only the access token, for $(...)
auth0-example get https://api.example.com/v1/me
auth0-example auth logout    # revokes the refresh token, deletes the tokens
```

## Set up Auth0

Exact screens change; the Auth0 documentation is the reference for each
step.

1. **An API** (Applications → APIs → Create API). Its *Identifier*, for
   example `https://api.example.com`, is the audience. Without an audience
   Auth0 issues a token that only works at `/userinfo`. Turn on *Allow
   Offline Access* if the CLI should stay signed in with a refresh token.
2. **For people, a Native application.**
   - Allowed Callback URLs: `http://127.0.0.1:8484/callback`. Auth0 matches
     the port, so the example uses a fixed one; change it with
     `AUTH0_REDIRECT_PORT` and register the same port.
   - Advanced Settings → Grant Types: *Authorization Code*, *Refresh Token*,
     and *Device Code* for the device flow (`auth login --flow device`, or
     automatically when no browser can be opened).
   - Refresh Token Rotation can stay on; the library stores each rotated
     token before using it.
3. **For machines, a Machine to Machine application** authorized for the API
   (the API's *Machine to Machine Applications* tab). With its secret set,
   the example uses the client credentials grant instead; there is no person,
   browser or refresh token.

## Run it

```bash
export AUTH0_DOMAIN=example.eu.auth0.com          # or your custom domain
export AUTH0_AUDIENCE=https://api.example.com
export AUTH0_CLIENT_ID=<the Native application's client ID>
go run ./examples/auth0 auth login
go run ./examples/auth0 auth status
```

For the Machine to Machine application, also set its secret. Read it from a
secret manager at run time; never compile it into a binary you distribute:

```bash
export AUTH0_CLIENT_ID=<the M2M application's client ID>
export AUTH0_CLIENT_SECRET=<its secret>
TOKEN=$(go run ./examples/auth0 auth token)
```

| Variable | Meaning |
|---|---|
| `AUTH0_DOMAIN` | Tenant or custom domain, without `https://`. Required. |
| `AUTH0_CLIENT_ID` | The application's client ID. Required. |
| `AUTH0_AUDIENCE` | The API identifier the tokens are for. |
| `AUTH0_CLIENT_SECRET` | Switches to client credentials (Machine to Machine). |
| `AUTH0_REDIRECT_PORT` | Loopback callback port of the browser flow; default `8484`. |

Tokens of a person are kept in the system keyring under the CLI's name and
per audience, so two audiences never share a token.

## Tests

- `cmd/root_test.go` runs this CLI's commands against an in-process server
  that behaves like Auth0 (`internal/oauthtest` with Auth0's discovery
  document): the device flow sends the audience and gets a refresh token,
  and a Machine to Machine secret switches to client credentials. They run
  with `just test`, without network access.
- `e2e/auth0_e2e_test.go` runs against a real tenant: discovery with the
  trailing-slash issuer, and client credentials whose access token names the
  audience. See [e2e/README.md](../../e2e/README.md#auth0).
