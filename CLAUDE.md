# Project rules

Conventions every contributor (human or agent) follows in this repo, enforced in review.
[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and release; this file and
`.claude/rules/` say what a change is held to. Link to them rather than restating them.

## What this is

- `github.com/nauthera/cobra-oauth2` is a Go library that adds OAuth 2.0 / OpenID Connect
  login to Cobra CLIs: `pkg/auth` (the `Client`, the flows, `Client.Transport`, the
  `auth login|logout|status|token` commands, provider presets) and `pkg/storage` (keyring,
  file, memory and fallback stores, the refresh lock). `internal/oauthtest` is the fake
  authorization server the tests use, `internal/cmd/demoidp` the one `just demo` records
  against, `examples/` the importer's view, `e2e/` the live tests.
- **It is a standards client, independent of nauthera-server.** It is developed alongside
  that server and tested against it, but it must work with every compliant provider. No
  code path branches on nauthera or any other provider by name; it reads discovery and
  follows the RFCs. A preset (`pkg/auth/presets.go`) only sets the issuer or static
  endpoints, default scopes, the client authentication style and the narrow quirks the
  provider documents. A nauthera-server bug is reported, not quietly absorbed: say so, and
  leave filing it there to a human (`.claude/rules/github-issues.md` § 1). A deviation
  worth tolerating is handled as any provider's would be (`.claude/rules/rfc-compliance.md`
  § 3).

## RFC first

- Protocol behaviour is decided by the specification, not by what one server does. Cite the
  section where the behaviour lives (`// RFC 8628 § 3.5: slow_down adds 5 seconds.`) and in
  the doc comment of an exported identifier that implements it.
- A change to what the library does on the wire updates
  [docs/rfc-support.md](docs/rfc-support.md), and a change to a preset or a tolerated
  deviation updates [docs/providers.md](docs/providers.md), in the same pull request. The
  steps are in `.claude/rules/rfc-compliance.md`.

## Security invariants

These hold for every change; [docs/security.md](docs/security.md) is the threat model and
CONTRIBUTING.md § 6 the full list. A change that weakens one is refused, not discussed.

- **No secret in output, logs or errors.** Access, refresh and ID tokens, client secrets,
  signing and DPoP keys, authorization and device codes, PKCE verifiers, `state` and
  `nonce` never reach an error message, a log record or a writer, except the access token
  on the `token` command's stdout. Errors carry the OAuth `error` code and a sanitized
  description, never a raw body. `storage.Token`, `auth.Client` and
  `auth.DeviceAuthorization` redact in `String`, `GoString` and `LogValue`; a new type
  holding a secret does the same.
- **Server strings are hostile.** Anything from a response that reaches a terminal or an
  error goes through `sanitize` (`pkg/auth/sanitize.go`); user codes through
  `validUserCode`. Bodies are read through the 1 MiB cap (`maxBodySize`, `pkg/auth/http.go`).
- **https only**, configured or discovered, except loopback (and `WithInsecureHTTP`, which
  stays explicit and off by default). TLS verification is never disabled. Only https or
  loopback URLs are printed or handed to the browser opener.
- **Mix-up and replay defences stay intact**: exact issuer match on discovery, RFC 9207
  `iss` on the redirect, PKCE S256 always, `state` and `nonce` from `crypto/rand` compared
  in constant time and used once, no redirects on back-channel POSTs.
- **`Client.Transport` is origin-bound**: the token goes only to the origins it is bound to
  (`WithAllowedOrigins`, the `WithResource` URLs, or the first request's origin), never
  across a cross-origin redirect, never over plain http to a remote host, never in a URL.
- **The loopback listener** binds `127.0.0.1` or `[::1]` only, accepts one valid response
  and shuts down on success, error or timeout.
- **Refresh tokens rotate safely**: the rotated token is stored before use, a spent one is
  never replayed, and refreshes are serialized in process and across processes
  (`storage.Locker`).
- **Library code never prints.** It writes to the writers it was given (`WithOutput`, the
  command's `OutOrStdout`/`ErrOrStderr`); forbidigo refuses `fmt.Print*` and the global
  `log`. No panics in library code.
- A vulnerability is reported through [SECURITY.md](SECURITY.md), never a public issue.

## Public API

- v1 is a compatibility promise (semantic versioning): code that builds against an earlier
  v1 keeps building and behaving the same. No exported identifier is removed or renamed,
  no signature changes, no default gets stricter in a way importers must react to. Grow
  the API instead: a new option, a new function, a new field. A change that cannot be made
  compatibly waits for a v2 (a new module path, `/v2`); propose it in an issue first. If
  one is ever needed, it is marked with `!` and a `BREAKING CHANGE:` footer
  (CONTRIBUTING.md § 8). Deprecate with a `// Deprecated:` paragraph that names the
  replacement, and keep the old identifier working.
- Every exported identifier has a doc comment saying what the caller can rely on (revive
  enforces it). Configuration is a functional option (`auth.WithXxx`), validated once in
  `NewClient`.
- `examples/` must build (`just examples`, CI) and the README's snippets must match the
  API. A change to an option, a command or a default updates both in the same PR.
- A new module dependency becomes every importer's; it needs a reason in the PR.

## Commands

- `just check` is the pre-PR gate (fmt, lint, vet, race tests with coverage, govulncheck,
  tidy, examples). `just test` runs the unit tests (`just test -run TestDevice ./pkg/auth`).
- `just e2e` runs the live tests against a nauthera-server (`e2e` build tag; variables in
  `e2e/README.md`). `just demo` re-records `demo.gif` against `internal/cmd/demoidp`.
  `just install-hooks` once, for the pre-commit and commit-msg hooks.

## Commits and pull requests

- Conventional Commits for every subject and every PR title, checked by
  `scripts/check-commit-msg.sh` (the commit-msg hook and CI). Types and scopes are in
  CONTRIBUTING.md § 8; the title becomes the release-notes line.
- Branch off `main`, one change per PR with its tests and docs, and link the issue in the
  PR body (`Closes #N`).

## Rule files

[`code-economy.md`](.claude/rules/code-economy.md) (search before you write, one owner per
rule, comments that say what is true now), [`go-testing.md`](.claude/rules/go-testing.md)
(parallel tests, the helpers that exist, fixtures, fuzz targets, no network or keyring),
[`rfc-compliance.md`](.claude/rules/rfc-compliance.md) (protocol changes and provider
quirks), [`github-issues.md`](.claude/rules/github-issues.md) (filing and labelling issues).
