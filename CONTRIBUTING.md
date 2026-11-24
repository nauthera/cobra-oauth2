# Contributing to cobra-oauth2

Thanks for contributing. `cobra-oauth2` is a small Go library that adds OAuth 2.0
/ OpenID Connect login to [Cobra](https://github.com/spf13/cobra) CLIs. It handles
other people's credentials, so we hold a high bar for correctness, security and
test coverage, while keeping the workflow light enough for a small project.

The conventions here follow nauthera-server's, the authorization server this
library is developed alongside, scaled down for a library. If anything here
conflicts with the code, the code wins; open a PR to fix the doc.

---

## 1. Prerequisites & getting started

- **Go**, at least the version in `go.mod`'s `go` directive. CI tests that
  minimum and the latest stable release; develop on the latest stable.
- **[just](https://github.com/casey/just)** for the task runner (optional: every
  recipe is a plain command you can copy out of the `justfile`).
- **[golangci-lint](https://golangci-lint.run/) v2**, at the version CI pins
  (`GOLANGCI_LINT_VERSION` in `.github/workflows/ci.yml`, `golangci_lint_version`
  in the `justfile`, currently v2.14.0). Install it with `just install-tools`,
  or with brew or the official install script, and check `golangci-lint version`.
  The version matters: a different one reports different findings, and a
  build made with an older Go than yours panics on the newer standard library.
  `just lint`, `just fmt` and the pre-commit hook check both
  (`scripts/check-golangci-lint.sh`) and print an install hint instead.
- **govulncheck** needs no install: `just vuln` runs the pinned version with
  `go run`.
- For the live tests only: a local **nauthera-server** (see § 5).

First run:

```bash
just install-hooks   # one-time: the pre-commit and commit-msg hooks (§ 2)
just test            # unit tests
just check           # the full local gate
```

---

## 2. Everyday commands

```bash
just                 # list the recipes
just check           # the full local gate: run this before every PR
just test            # go test ./...   (args pass through: just test -run TestX ./pkg/auth)
just test-race       # race detector
just cover           # coverage profile + coverage.html
just lint            # golangci-lint run (.golangci.yml)
just fmt             # format (gofumpt + goimports through golangci-lint)
just vet             # go vet, the e2e-tagged packages included
just tidy            # go mod tidy + verify
just vuln            # govulncheck, pinned
just examples        # build every example
just e2e             # live tests against a running nauthera-server (§ 5)
just release-notes v0.3.0   # preview a release's notes (§ 8)
```

### Two tiers: the hooks and `just check`

`just check` runs formatting, lint, vet, race tests with coverage, govulncheck,
the tidy check and the examples build: what CI runs, on your platform. Run it
**before opening a PR**, not on every commit.

For the per-commit tier, `just install-hooks` writes two plain git hooks (no
hook framework, the same mechanism as nauthera-server):

- **pre-commit** checks that the **staged** content of each `.go` file is
  formatted, and runs `go vet` on the packages they belong to. It never
  rewrites or re-stages anything, so hunks you left out with `git add -p`
  stay out of the commit. When a file is not formatted it stops and asks you
  to run `just fmt` and stage the result. It takes a second or two.
- **commit-msg** checks the message against Conventional Commits (§ 7) with
  `scripts/check-commit-msg.sh`, the script CI runs on the pull request.

Bypass both for a single commit with `git commit --no-verify`, and re-run
`just install-hooks` after the recipe changes.

---

## 3. Repository layout

- `pkg/` holds the library's packages (the auth flows and cobra commands, the
  token storage providers).
- `examples/` holds small programs that use the library the way an importer
  would. They are part of the module and CI builds them, so an API change has
  to update them.
- `e2e/` holds the live tests against a real nauthera-server, behind the `e2e`
  build tag (§ 5).
- `scripts/` holds the shell scripts the hooks, CI and releases share.

---

## 4. Code style & conventions

- **`gofumpt`/`goimports` clean.** Run `just fmt`; the pre-commit hook checks it.
- **Match the surrounding code.** Comment density, naming and idiom should be
  indistinguishable from the file you're editing.
- **Doc comments on every exported identifier** (revive enforces it). Explain
  *why* and what the caller can rely on, not the signature.
- **Errors are wrapped with `%w`** and say what was being done, lowercase and
  without trailing punctuation: `fetch discovery document: %w`, never
  "failed to …", which a wrapped chain repeats at every level. Sentinels are
  `ErrXxx`, error types `XxxError` (errname enforces it). An OAuth error
  response (RFC 6749 § 5.2) surfaces as a typed error carrying its `error`
  code, so callers can branch with `errors.As`.
- **No panics in library code.** Return an error.
- **Context-aware I/O.** Every HTTP request is built with
  `http.NewRequestWithContext` (noctx enforces it), and every wait (device-flow
  polling, the loopback listener) stops when the context is done.
- **Injectable dependencies.** The `*http.Client`, the clock where timing
  matters, and the output writers come in through options, with safe defaults,
  so callers can configure proxies and TLS and tests can run without the
  network.
- **No printing from library code.** Write to the `io.Writer` the caller
  configured, or the cobra command's `OutOrStdout()`/`ErrOrStderr()`;
  `fmt.Print*` and the global `log` are refused by forbidigo outside
  `examples/`.
- **Functional options** (`auth.WithXxx`) for configuration; validate the
  result once, up front, and return a clear error.
- **Minimal dependencies.** Prefer the standard library and small, vetted
  modules. Every requirement in `go.mod` becomes a requirement of every
  importer, so a new dependency needs a justification in the PR.

---

## 5. Testing

- **Unit tests** run with `just test` and need no network. HTTP flows are
  tested against `httptest` servers through the injectable `*http.Client`;
  tests that wait (polling intervals, expiry) use an injected clock or short
  intervals rather than sleeping.
- **Table-driven tests** for pure logic, one behaviour per case with a clear
  name. Use `t.Parallel()` where the test owns its state.
- **Race detector** (`just test-race`) for anything with goroutines, the
  loopback listener, polling, or shared state; `just check` and CI always run
  with `-race`.
- **Security invariants get explicit tests**: a mismatched `state` is refused,
  PKCE is always S256, a discovery document whose `issuer` differs from the
  configured one is refused, `slow_down` lengthens the polling interval, no
  token reaches an error message or the output, and so on.
- **Provider fixture tests.** Discovery documents and token/error responses
  recorded from nauthera-server (and from other providers we support) are
  replayed from `testdata/` by an `httptest` server in the ordinary suite, so
  the library is checked against the shapes real servers send without a live
  one. To refresh a nauthera fixture, run a local nauthera-server, fetch the
  document or response, **redact every token, secret and code**, and commit
  the file with the test change that needs it. Prefer adding a fixture for a
  new provider quirk over special-casing a provider in code.
- **Live tests (opt-in).** `e2e/` runs the real flows against a running
  nauthera-server. They are behind the `e2e` build tag, so neither `just test`
  nor CI runs them. To run them:
  1. Run a nauthera-server locally, as its own CONTRIBUTING.md describes.
  2. Register a **public** client on it with the **device authorization
     grant** (and the authorization code grant with a **loopback redirect
     URI**, `http://127.0.0.1/…`, if you are testing the browser flow), plus
     anything else the test you are running needs.
  3. Export the settings the tests read, at least
     ```bash
     export NAUTHERA_E2E_ISSUER=https://localhost:8080   # your server's issuer URL
     export NAUTHERA_E2E_CLIENT_ID=<the client id>
     ```
     and any further `NAUTHERA_E2E_*` variable the tests' package comment
     lists. A `.env` file is git-ignored if you want to keep them around.
  4. `just e2e` (args pass through: `just e2e -run TestDevice`).

  A local server with a self-signed certificate: trust its CA for the test run
  (for example `SSL_CERT_FILE=<its CA bundle> just e2e`), never by turning off
  TLS verification. The exact steps on the server side change with the server;
  its CONTRIBUTING.md is the reference, not this file.
- **Coverage.** New code should not lower the coverage of the package it lives
  in. `just cover` writes `coverage.html`; CI uploads the profile to Codecov.

---

## 6. Security practices

This library holds user credentials on behalf of someone else's CLI, so every
change is security-relevant. Rules for code in this module:

- **Secure by default.** Endpoints must be `https`, except loopback addresses
  for local development and the loopback redirect (RFC 8252 § 8.3). TLS
  verification is never disabled by the library. An insecure option, if one is
  ever needed, is explicit, named as such, and off by default.
- **Never print, log or wrap a secret.** Access tokens, refresh tokens, ID
  tokens, client secrets, device codes and authorization codes never appear in
  error messages or output, except where printing the token is the command's
  explicit job (the `token` command), and then only to the command's output
  writer. Error messages carry the OAuth `error` code and description, not the
  raw response body.
- **PKCE with S256** for every authorization code flow (RFC 7636, RFC 9700),
  never `plain`.
- **`state` (and `nonce` for OpenID Connect) from `crypto/rand`**, at least
  128 bits, compared in constant time, single use. `math/rand` is refused by
  the linter.
- **Loopback redirect listener** binds `127.0.0.1` or `[::1]` (never all
  interfaces) on an ephemeral port, accepts one valid response, and shuts down
  on success, error or timeout (RFC 8252 § 7.3).
- **Validate the issuer.** A discovery document's `issuer` must equal the
  configured issuer (RFC 8414 § 3.3, OpenID Connect Discovery § 4.3), and an
  authorization response's `iss` parameter is checked when the server
  advertises it (RFC 9207), to stop mix-up attacks.
- **Device flow** (RFC 8628 § 3.5) honours `interval`, adds 5 seconds on
  `slow_down`, stops at `expires_in`, on `access_denied` and on
  `expired_token`, and stops when the context is cancelled.
- **Treat access tokens as opaque.** Do not parse an access token to make a
  decision. An ID token used for identity is validated (signature against the
  issuer's JWKS, `iss`, `aud`, `exp`, `nonce`).
- **Bound what you read.** Responses are read through a size limit, and
  requests have timeouts through the context or the client.
- **Store tokens safely.** The OS keyring is the default store; a file store
  writes `0600` files under the user's config directory. Stored tokens are
  keyed so that two issuers or two clients cannot read each other's.
- **Dependencies are part of the attack surface.** `govulncheck` runs on every
  PR; keep the dependency list short.
- If your change has a security dimension you are unsure about, say so in the
  PR's "Security impact" section and ask for review. To report a
  vulnerability, follow [SECURITY.md](SECURITY.md), never a public issue.

---

## 7. Working alongside nauthera-server

nauthera-server is this library's reference authorization server: the live
tests run against it, and its fixtures are in the unit suite. The library is
nevertheless a **standards client**, not a nauthera client. It relies on
discovery and the RFCs, never on server internals, so that it works with as
many providers as possible.

The two repositories share their conventions, so moving between them costs
nothing: Conventional Commits, `just check` before a PR, `just install-hooks`
for the fast tier, golangci-lint v2 at the same pinned version, Dependabot as
the only dependency bot, SHA-pinned actions, tag-driven releases whose notes
come from the commits. When one repository moves a shared convention (a
golangci-lint bump, a new commit type), move the other one in the same week
if you can, but neither blocks on the other.

How changes usually flow, as a guide rather than a procedure:

- **The server adds or changes protocol behaviour** (a new grant, a discovery
  field, an error code): once it is on the server's main branch, add or
  refresh the fixture here, run `just e2e` against a local server built from
  that main, and adapt the library if needed. If the change breaks a client
  that follows the RFCs, raise it on the server side first.
- **The library needs something from the server** (an endpoint, metadata, a
  grant it does not offer yet): open an issue on nauthera-server naming the
  standard and section. Meanwhile, test the library against the fixture or
  another provider that implements it.
- **A fix spans both**: land and release the server side first, then the
  library, each in its own PR and each with its own release notes. Link the
  two PRs.
- **Behaviour differs between providers**: the RFC decides. Where a widely
  used provider deviates, a tolerant default or an option is fine; capture the
  deviation in a fixture test, so it is not lost in a refactor.

---

## 8. Commits & pull requests

- **Branch** off `main`; do not commit to it directly.
- Keep PRs focused: one change, its tests and its docs.
- Never commit build output, coverage files, `.env` files or real tokens.

### Conventional Commits

Every commit subject and every PR title follows
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
type(scope)!: description

optional body, wrapped at 72 columns, saying why

BREAKING CHANGE: what an importer must change (optional footer)
```

**Types** (the ones `scripts/check-commit-msg.sh` accepts and
`scripts/release-notes.sh` groups by):

| type       | for                                                   | in the release notes |
| ---------- | ----------------------------------------------------- | -------------------- |
| `feat`     | a new capability for importers                        | Features             |
| `fix`      | a bug fix                                             | Bug fixes            |
| `perf`     | a performance improvement                             | Performance          |
| `revert`   | reverting an earlier change                           | Reverts              |
| `docs`     | documentation only                                    | Documentation        |
| `refactor` | a change that neither fixes a bug nor adds a feature  | Maintenance          |
| `test`     | tests only                                            | Maintenance          |
| `build`    | build system, `go.mod`, tooling                       | Maintenance          |
| `ci`       | workflows and the scripts CI runs                     | Maintenance          |
| `chore`    | anything else that does not touch the library's code  | Maintenance          |
| `style`    | formatting only                                       | Maintenance          |

**Scopes** are optional, lowercase, and name the area a reader of the release
notes would look for. The usual ones: `auth`, `device`, `pkce`, `dpop`,
`storage`, `discovery`, `cmd`, `examples`, `e2e`, `deps`, `ci`, `docs`. Use a
new one when none fits; several are joined with a comma (`fix(device,pkce):`).
`deps` is special: the release notes fold it into the "Dependencies" block,
and Dependabot uses it (`chore(deps):`, `ci(deps):`).

**Descriptions** are imperative and lowercase-first unless they start with a
name (`feat(dpop): add DPoP proof signing`), with no trailing period. Keep the
subject to 72 characters; the check refuses more than 100.

**Breaking changes** (anything that makes an importer change their code or
see different behaviour) get a `!` after the type or scope **and** a
`BREAKING CHANGE:` footer explaining the migration:

```
feat(storage)!: key stored tokens by issuer and client id

BREAKING CHANGE: StorageProvider.GetToken now takes a Key. Wrap the client id
you passed before with storage.KeyFor(issuer, clientID).
```

The release notes list either form under "Breaking changes" first. Before
v1.0.0 a breaking change ships in a new minor version (v0.3.0 → v0.4.0), and
its footer is what importers read in the release notes, so say there what to
change.

`git commit --fixup` / `--squash` commits are accepted locally by the hook,
but CI refuses them in a PR: squash them before merging
(`git rebase -i --autosquash main`). Subjects git writes itself (`Merge …`,
`Revert "…"`) are accepted.

### Pull requests

- The **PR title** is a Conventional Commit too, and it matters most: it
  becomes the merge commit's subject (the repository's merge setting uses the
  PR title, for merge and squash merges alike) and so the line in the release
  notes. CI checks the current title, so after fixing it, re-run the job.
- Fill in the template: what and why, the type of change, breaking changes,
  the security impact ("None" is a valid answer, but say so), and how you
  tested it.

### What CI runs

`.github/workflows/ci.yml` runs on every pull request and every push to
`main`; a newer push to a PR cancels the older run.

| job                                | what                                                                    | locally                |
| ---------------------------------- | ----------------------------------------------------------------------- | ---------------------- |
| actions are pinned by commit SHA   | every `uses:` is a full commit SHA with a `# vX.Y.Z` comment            | (read the diff)        |
| lint                               | golangci-lint (formatting included), `go vet -tags e2e`                 | `just lint`, `just vet` |
| test                               | race tests with coverage on Linux, macOS and Windows, on go.mod's minimum Go and the latest stable; coverage to Codecov from one of them | `just test-race-cover` |
| known vulnerabilities              | govulncheck on the latest stable Go                                     | `just vuln`            |
| go.mod and go.sum are tidy         | `go mod tidy -diff`, `go mod verify`                                    | `just tidy-check`      |
| examples build                     | `go build ./examples/...`                                               | `just examples`        |
| conventional commits (PRs only)    | the PR title and every commit subject                                   | the commit-msg hook    |

`just check` covers everything but the other platforms, the minimum Go, the
SHA pins and the PR title. The live tests (`just e2e`) need a server and do
not run in CI.

Every action is pinned by commit SHA, and each job has the least permissions
it needs (read-only unless it says otherwise). Dependabot
(`.github/dependabot.yml`) proposes Go module and action updates weekly,
grouped, after a short cooldown, and security updates right away. Renovate
is switched off (`.github/renovate.json`).

### Releasing

A pushed tag is the only thing that publishes, through
`.github/workflows/release.yml`. There are no binaries: a release is the tag,
which the Go module proxy serves, plus a GitHub release with notes.

- `vX.Y.Z` is a release. It must name a commit that was `main`'s head.
- `vX.Y.Z-rc.N` is a release candidate, published as a GitHub pre-release,
  and may be tagged on any branch.

Pick the version from what landed since the last release: before v1.0.0 a
breaking change or a feature bumps the minor version, a fix the patch
version. Then:

```bash
git switch main && git pull
git tag -a v0.4.0 -m v0.4.0
just release-notes v0.4.0     # preview; `git tag -d v0.4.0` backs out before the push
git push origin v0.4.0
```

The workflow checks the tag, runs the build and tests once more, writes the
notes with `scripts/release-notes.sh` (the conventional subjects since the
previous `vX.Y.Z`, grouped by type and sorted by scope, with maintenance and
dependency updates folded away) and asks the module proxy for the new
version so it shows up on pkg.go.dev. A release with a serious bug is not
deleted (the proxy keeps it anyway): fix forward, and add a `retract`
directive to `go.mod` in the fix's release.

### Definition of done (checklist before you open a PR)

- [ ] **`just check` passes** (fmt, lint, vet, race tests, govulncheck, tidy,
      examples).
- [ ] New or changed behaviour has tests, including the security invariants
      it touches; a provider quirk has a fixture test.
- [ ] If you changed a flow, `just e2e` passes against a local nauthera-server
      (or the PR says why it could not be run).
- [ ] New exported identifiers have doc comments; the README and the examples
      match the API.
- [ ] No token, secret or code reaches an error message, a log or the output.
- [ ] The PR title and the commits follow Conventional Commits; a breaking
      change has `!` and a `BREAKING CHANGE:` footer saying what to change.
- [ ] A new dependency is justified in the PR description.

---

Questions, or a design you want to sanity-check before building it? Open a
draft PR or an issue. Thank you for keeping the bar high.
