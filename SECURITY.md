# Security policy

`cobra-oauth2` handles OAuth 2.0 tokens on behalf of command-line tools: it
obtains them, stores them and hands them to the program that embeds it. A flaw
here can leak a user's credentials, so we treat security reports as the
highest-priority work on the project.

## Supported versions

Fixes land on `main` and ship in the next patch release of the **latest minor
version** of the current major version; older minors do not get backports. A v1
minor release never breaks code that builds against an earlier v1, so moving
to the latest one is always the upgrade path.

| Version             | Supported           |
| ------------------- | ------------------- |
| latest `v1.x` minor | :white_check_mark:  |
| older `v1.x`        | :x: (upgrade within v1) |
| `v0.x`, untagged    | :x:                 |

## Reporting a vulnerability

Please report vulnerabilities **privately**, through GitHub's private
vulnerability reporting:

1. Open <https://github.com/nauthera/cobra-oauth2/security/advisories/new>
   (repository → **Security** → **Report a vulnerability**).
2. Describe the issue, its impact, the affected version or commit, and how to
   reproduce it (a failing test or a minimal program is ideal).

- **Do not** open a public issue, discussion or pull request for a
  vulnerability.
- **Do not** include live tokens, client secrets, or credentials for real
  accounts. Redact them, or reproduce against a throwaway client.

We will acknowledge the report, keep you updated while we work on a fix, agree
a disclosure date with you, and publish a GitHub security advisory (with a CVE
where one applies) when the fixed release is out. We are glad to credit
reporters who want to be named.

## Scope

In scope: anything in this module that could expose or misuse a token or
secret, for example

- tokens, refresh tokens, client secrets or device codes printed, logged,
  written into error messages, or stored somewhere other than the configured
  storage provider;
- weaknesses in the flows the library implements: PKCE, `state` and `nonce`
  handling, redirect / loopback listener handling, device-flow polling, issuer
  and discovery validation, token response validation;
- insecure defaults, such as accepting plain `http` endpoints outside loopback
  or skipping TLS verification;
- token storage that is readable by other users or processes it should not be.

Out of scope here, but welcome at the right place:

- vulnerabilities in an authorization server (report them to its maintainers;
  for nauthera-server, follow its own security policy);
- vulnerabilities in a dependency that this module does not make reachable
  (`govulncheck` runs on every pull request; report the dependency upstream);
- the security of the machine the CLI runs on (a local administrator can read
  the OS keyring).

## How we keep the module secure

- Every pull request runs `govulncheck`, `gosec` (through golangci-lint) and
  the race detector; see [CONTRIBUTING.md](CONTRIBUTING.md).
- GitHub Actions are pinned by commit SHA and workflows run with least
  privilege; Dependabot proposes dependency and action updates weekly, and
  security updates as soon as they are published.
- [CONTRIBUTING.md](CONTRIBUTING.md) ("Security practices") lists the rules
  code in this module follows.
