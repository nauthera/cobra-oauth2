<!--
Thanks for contributing! Keep PRs focused. See CONTRIBUTING.md for conventions.

The PR title is a Conventional Commit, checked by CI, and becomes the merge
commit's subject and the line in the release notes:
  feat(device): honour the slow_down error
  fix(storage)!: key stored tokens by issuer and client id
The module is v1: a breaking API change cannot be released without a v2, so
open an issue before making one, mark it with `!` and describe it under
"Breaking changes".
-->

## What & why

<!-- What does this change and why? Link any issue: Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Breaking change (exported API or behaviour; needs a v2, see CONTRIBUTING.md; `!` in the title, details below)
- [ ] Refactor / internal
- [ ] Docs / tooling / CI
- [ ] Dependency update

## Breaking changes

<!-- Delete if none. Otherwise: what an importer has to change, before → after. -->

## Security impact

<!-- Anything touching tokens, secrets, storage, transport, redirects, state,
PKCE, discovery or what the commands print? "None" is a valid answer, but say
so explicitly for an OAuth client library. -->

## Tested against

<!-- Unit tests only, or also live: `just e2e` against nauthera-server, or a
manual run against another provider (which one). -->

## Checklist (see CONTRIBUTING.md → Definition of done)

- [ ] `just check` passes locally (fmt, lint, vet, race tests, govulncheck, tidy, examples)
- [ ] New/changed behaviour has tests, including the relevant security invariants
- [ ] New exported identifiers have doc comments; the README is updated if the usage changed
- [ ] No token, secret or device code is printed, logged or put in an error message
- [ ] Commits and the title follow Conventional Commits (`just install-hooks` checks commits locally)
