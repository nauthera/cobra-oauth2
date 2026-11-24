# Protocol behaviour and RFC compliance

Enforced in review. Applies to every change to what the library sends, accepts or refuses
on the wire, and to every preset, by a person or an agent.

The library is a client of the standards, not of a server: CLAUDE.md lists the ones it
implements, and [docs/rfc-support.md](../../docs/rfc-support.md) says section by section
what it does with each.

## 1. Start from the specification

- Find the section that governs the behaviour and read its MUST, SHOULD and MAY. The
  client-side rules are often in a different section from the server's (RFC 8628 § 3.5 for
  polling, RFC 6749 § 5.2 for errors, OpenID Connect Core § 3.1.3.7 for ID tokens), and a
  later document may tighten an earlier one (RFC 9700 over RFC 6749, RFC 9207 for mix-up).
- A MUST is implemented and tested. A SHOULD is implemented unless there is a reason, and
  the reason goes in `docs/rfc-support.md`. A MAY is implemented only for a real caller.
- When the specification and a server disagree, the specification wins; a tolerated
  deviation is § 3. When the specification is silent, pick the conservative reading
  (refuse, do not guess) and say so in the matrix.
- Cite the section in a comment where the behaviour lives and in the doc comment of the
  exported identifier that exposes it: `// RFC 9449 § 8: retry once with the server's
  nonce.` Cite, do not paste the RFC text.

## 2. Pin it with a test

- The rule gets a table of cases in the test file of the code that owns it, including the
  refusals: the wrong `iss`, the missing parameter, the `http` endpoint, the oversized body.
- Server behaviour the test needs is an `oauthtest` feature: a `Config` field, a `Quirks`
  field or an `Endpoint` override, added there rather than as a handler in one test file
  (`go-testing.md`). `oauthtest` follows the specifications strictly, so a client that
  passes only because the fake is lax is caught.
- A response shape recorded from a real server is a fixture: nauthera-server under
  `pkg/auth/testdata/nauthera/` (listed in its `README.md`), other providers under
  `pkg/auth/testdata/providers/<provider>/`. Redact every token, code, nonce and secret.
- A new parser of server or browser input gets a fuzz target in `pkg/auth/fuzz_test.go`.
- A change to a flow runs `just e2e` against a local nauthera-server when you can, or the PR
  says why it could not.

## 3. Provider quirks

Real providers deviate. Handle a deviation in the first of these that fits:

1. **A tolerant default for everyone**, when accepting it cannot weaken a check: a number
   sent as a string, `verification_url`, an error body at HTTP 200, a comma-separated
   scope. It goes in the parser that owns the field (`pkg/auth/response.go`, `device.go`) and
   in the "Handled for every provider" list of [docs/providers.md](../../docs/providers.md).
2. **A preset setting**, when only some providers need it or it relaxes a check: a static
   endpoint, the secret in the body, the assertion audience, an issuer alias. The preset in
   `pkg/auth/presets.go` sets a config field that the protocol code reads. Code never
   branches on the provider's name; give the behaviour a field instead (as `exactRedirectPort`
   does for Cognito's exact callback matching).
3. **An option for importers** (`WithAuthMethod`, `WithAuthParam`, `WithRedirectHost`, …),
   when the deviation depends on how the provider is configured rather than on the
   provider.

A relaxed check stays as narrow as the provider's documentation allows (the Entra ID
`{tenantid}` template, Google's second issuer spelling), and never loosens it for other
providers. Reproduce the provider in a test: an `oauthtest.Quirks` setting plus, where you
have one, its fixture, in `providers_test.go`. A deviation that cannot be handled without
weakening a security invariant (CLAUDE.md) is documented as a limit, not handled.

## 4. Update the documents in the same change

- `docs/rfc-support.md`: the row for the section, its status (`yes`, `opt-in`,
  `partial`, `no`) and what the notes say the library does. A new specification adds a
  summary row and its own table.
- `docs/providers.md`: the provider's section and the "At a glance" table for a preset
  change, the "Handled for every provider" list for a tolerant default.
- The README's "Standards" and "Providers" tables when a summary line changes, and
  `docs/nauthera.md` when what the library does with nauthera-server changes.
- A change in what an importer sees on the wire or in an error is a breaking change when
  they must react to it (CLAUDE.md, "Public API").
