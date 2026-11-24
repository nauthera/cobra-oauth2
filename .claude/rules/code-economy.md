# Code economy

Enforced in review. Applies to every change, by a person or an agent.

Agent-written code fails in known ways: logic solved twice because the first copy was not
found, comments that narrate the editing session, abstractions with one caller, and tests
that outweigh the code. The yardstick is **lines a maintainer must read**, not lines
written. This module is small; keep it that way.

## 1. Search before you write

A helper you are about to write probably exists. Search by behaviour, not by the name you
had in mind (`grep -rn "ConstantTimeCompare" pkg`, `grep -rn "isLoopback" pkg`), and look
at the owner first:

| Rule | Owner |
| --- | --- |
| Back-channel HTTP: bounded reads, no redirects, same-origin GETs, endpoint and loopback checks, URL-free transport errors | `pkg/auth/http.go` (`readBody`, `noRedirectClient`, `sameOriginRedirectClient`, `validateEndpoint`, `isLoopbackHost`, `redactURLError`) |
| Parsing a token or error response, numbers as strings, `token_type`, `scope` | `pkg/auth/response.go` (`parseFields`, `checkResponse`, `tokenFromFields`, `normalizeScope`) |
| OAuth errors and their sentinels | `pkg/auth/errors.go` (`OAuthError`, `StatusError`, `configErr`) |
| Making a server string safe to print | `pkg/auth/sanitize.go` (`sanitize`, `validUserCode`) |
| Client authentication, assertions | `pkg/auth/clientauth.go` |
| Discovery, the issuer check and its preset exceptions | `pkg/auth/discovery.go` (`issuerMatches`) |
| URLs handed to the browser | `pkg/auth/browser.go` (`safeBrowserURL`) |
| Provider settings | `pkg/auth/presets.go` (`preset`, `presetScopes`, `httpsBase`) |
| Storage keys, token redaction | `pkg/storage/token.go` (`Key`, `Token.String`/`GoString`/`LogValue`) |
| Cross-process refresh lock | `pkg/storage/lock.go` (`Locker`, `NewFileLocker`) |

The standard library comes before a helper of ours, and a helper of ours before a new
dependency (`slices`, `maps`, `min`/`max`, `strings.Cut*`, `crypto/subtle`). If what exists
is almost right, extend it; a second copy "with one difference" is the bug.

## 2. One owner per rule

A rule (a validation, a mapping, a protocol constant) lives in one place and every caller
goes through it. When you find a second copy, delete one; do not make both agree. Every
response a server sends is parsed through `response.go`, every endpoint URL checked through
`validateEndpoint`, every printed server string sanitized through `sanitize`.

## 3. Abstractions pay rent

- No new package without a second importer; a function with one caller lives beside it.
  New exported API is a promise to every importer (CLAUDE.md, "Public API"): add it only for
  a real caller outside the package.
- An interface is declared where it is consumed, with the methods that consumer uses, and
  only when there are two real implementations (`storage.Provider`, `auth.Clock`,
  `ClientAuthenticator`). A test fake alone does not justify one: use `storage.NewMemory()`
  or `oauthtest.Server`.
- No functional option for a single caller inside the module, no defensive branch for a
  state an earlier check rules out, no wrapper that forwards and adds nothing.
- A provider difference is a config field a preset sets, never a branch on the provider's
  name (`rfc-compliance.md` § 3).

## 4. Comments say what is true now, and why

- **Keep**: the reason for a non-obvious choice, an invariant a caller must hold, a spec
  citation (`RFC 9449 § 8`), a trap.
- **Delete**: a comment that restates the line below it, or a doc comment that repeats the
  signature (`// NewFoo returns a new Foo`).
- **Never write history**: no issue or PR numbers, no "used to", "previously", "moved
  here", "before this change". Git holds the history. Do not name a test from production
  code; name code only as a godoc link (`[Client.Transport]`).
- **A comment is true or it is deleted.** When you change what code does, the comment above
  it is part of the change, and so are the docs that describe it.
- **Short**: under about fifteen lines, no CAPITALS for stress, no "deliberately",
  "importantly", "note that". State the reason once.

## 5. Tests are proportionate

One property, one tier, one fixture: a rule is pinned once, as a table in the test file of
the code that owns it, and a flow test asserts only what the flow adds. Build on the
helpers in `go-testing.md`; never a second fake server or clock in a new file.

## 6. Documentation is code

`README.md`, `CONTRIBUTING.md`, `docs/*.md`, `CLAUDE.md` and `.claude/rules/*.md` describe
the tree as it is; a sentence that became false is fixed in the PR that made it false. Each
topic has one home: the README orients, CONTRIBUTING says how to work, `docs/rfc-support.md`
and `docs/providers.md` say what the library does, `docs/security.md` is the threat model,
`.claude/rules/` holds what review enforces. Link, do not restate.
