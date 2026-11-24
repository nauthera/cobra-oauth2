# justfile — task runner for cobra-oauth2.
# Install just: https://github.com/casey/just  |  Run `just` to list targets.
#
# Every recipe is a plain command you can copy out of this file; just is a
# convenience, not a requirement.

set positional-arguments

# ---- Pinned tool versions ---------------------------------------------------
# Keep these equal to .github/workflows/ci.yml (GOLANGCI_LINT_VERSION,
# GOVULNCHECK_VERSION) so local and CI results agree, and close to
# nauthera-server's pins so both projects lint alike. Bump them together.
#
# nauthera-server pins govulncheck with a go.mod `tool` directive. A library's
# go.mod is part of what every importer resolves, so a tool requirement there
# would add the tool's dependency graph to theirs; this module runs it with
# `go run pkg@version` instead, which is just as reproducible.
golangci_lint_version := "v2.14.0"
govulncheck_version   := "v1.10.0"

# Coverage profile written by `test-race-cover` and `cover`.
coverprofile := "coverage.out"

# Default target: show the available recipes.
default:
    @just --list

# ---- The two gates ------------------------------------------------------------

# `just check` is the pre-PR gate. It runs what CI's lint, test, vuln and tidy
# jobs run, on your platform and Go only (CI adds macOS, Windows and the oldest
# Go that go.mod allows). It does not check commit subjects or the pull
# request title: the commit-msg hook (`just install-hooks`) covers the first,
# and the second only exists on GitHub.
#
# Run the full local gate before opening a pull request.
check: fmt-check lint vet test-race-cover vuln tidy-check examples
    @echo "==> all checks passed"

# pre-commit is the cheap tier: it only checks what is STAGED. Everything
# expensive (race tests, coverage, govulncheck) stays in `just check` and CI.
# commit-msg holds each message to Conventional Commits with
# scripts/check-commit-msg.sh, the same script CI runs on a pull request's
# title and commits.
#
# The pre-commit hook never rewrites or re-stages files. Re-staging a whole
# file after formatting it would also commit the hunks left out with
# `git add -p`. It checks the staged content instead (what `git show :file`
# prints) and, when that is not formatted, stops with a hint to run
# `just fmt` and stage the result.
#
# Deliberately plain git hooks, as in nauthera-server, not the `pre-commit`
# framework or lefthook: two short scripts do not need another toolchain.
# Re-run this recipe after editing the hook bodies. Bypass a single commit
# with `git commit --no-verify`.
#
# Install the git hooks: a fast pre-commit hook (~1-2s) and a commit-msg hook.
install-hooks:
    #!/usr/bin/env bash
    set -euo pipefail
    hooks="$(git rev-parse --git-path hooks)"
    mkdir -p "$hooks"

    cat >"$hooks/pre-commit" <<'HOOK'
    #!/usr/bin/env bash
    # Managed by `just install-hooks` — re-run that recipe to update.
    # Fast tier only: check the formatting of the STAGED content and vet the
    # touched packages. Nothing is rewritten or re-staged. The full gate is
    # `just check`.
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)"
    cd "$root"

    # NUL-separated, so paths with spaces survive. --diff-filter=d skips
    # deletions (nothing left to check).
    staged=()
    while IFS= read -r -d '' f; do
        staged+=("$f")
    done < <(git diff --cached --name-only -z --diff-filter=d -- '*.go')
    [ "${#staged[@]}" -gt 0 ] || exit 0

    if [ -x scripts/check-golangci-lint.sh ]; then
        scripts/check-golangci-lint.sh || { echo "pre-commit: (or commit with --no-verify)" >&2; exit 1; }
    fi

    echo "pre-commit: golangci-lint fmt (staged content)"
    unformatted=()
    for f in "${staged[@]}"; do
        # The index version, not the working tree: unstaged hunks are not
        # part of this commit and must not decide the check.
        if ! git show ":$f" | golangci-lint fmt --stdin 2>/dev/null | cmp -s - <(git show ":$f"); then
            unformatted+=("$f")
        fi
    done
    if [ "${#unformatted[@]}" -gt 0 ]; then
        echo "pre-commit: not formatted (staged version):" >&2
        printf '    %s\n' "${unformatted[@]}" >&2
        echo "pre-commit: run 'just fmt', review the change and stage it" >&2
        exit 1
    fi

    # go vet is per-PACKAGE, not per-file: derive the touched packages. The e2e
    # tag is set so a package whose files are all tagged is vetted, not refused.
    pkgs=()
    while IFS= read -r d; do
        pkgs+=("./$d")
    done < <(for f in "${staged[@]}"; do dirname -- "$f"; done | sort -u)
    echo "pre-commit: go vet ${pkgs[*]}"
    go vet -tags e2e "${pkgs[@]}"
    HOOK

    cat >"$hooks/commit-msg" <<'HOOK'
    #!/usr/bin/env bash
    # Managed by `just install-hooks` — re-run that recipe to update.
    # Conventional Commits, checked by the script CI runs (CONTRIBUTING.md).
    set -euo pipefail
    script="$(git rev-parse --show-toplevel)/scripts/check-commit-msg.sh"
    # A branch from before the script existed has nothing to run.
    [ -x "$script" ] || exit 0
    exec "$script" "$1"
    HOOK

    chmod +x "$hooks/pre-commit" "$hooks/commit-msg"
    echo "==> installed $hooks/pre-commit and $hooks/commit-msg"
    echo "    pre-commit: formatting check + go vet (staged .go, nothing rewritten)"
    echo "    commit-msg: Conventional Commits (scripts/check-commit-msg.sh)"
    echo "    bypass once with: git commit --no-verify"

# ---- Everyday -----------------------------------------------------------------

# Extra args go to `go test` and replace ./...: `just test -run TestDevice ./pkg/auth`.
#
# Run the unit tests.
test *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ $# -eq 0 ]; then set -- ./...; fi
    go test "$@"

# Run the unit tests with the race detector (needs cgo).
test-race:
    CGO_ENABLED=1 go test -race ./...

# -coverpkg counts a statement reached from another package's test too; the
# examples are left out of it, since nothing tests them and they would only
# dilute the number.
#
# Race tests and the coverage profile in one pass, as CI's test job runs them.
test-race-cover:
    #!/usr/bin/env bash
    set -euo pipefail
    coverpkg=$(go list ./... | grep -vE '/examples/|/internal/cmd/' | paste -sd, -)
    CGO_ENABLED=1 go test -race -covermode=atomic -coverpkg="$coverpkg" -coverprofile={{coverprofile}} ./...

# Prints the total; `go tool cover -func=coverage.out` prints the
# per-function table afterwards.
#
# Write the coverage profile and an HTML report (coverage.html) to open in a browser.
cover: test-race-cover
    go tool cover -func={{coverprofile}} | tail -n 1
    go tool cover -html={{coverprofile}} -o coverage.html
    @echo "==> wrote coverage.html"

# The tests live in ./e2e behind the `e2e` build tag, so `just test` and CI
# never run them. They read the server and the client to use from the
# environment; e2e/README.md lists the variables and how to set a server up.
# Extra args go to `go test`: `just e2e -run TestDevice`. The timeout leaves
# room for the interactive login (NAUTHERA_E2E_INTERACTIVE=1), which waits up
# to ten minutes for a person.
#
# Run the opt-in end-to-end tests against a running nauthera-server.
e2e *args:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NAUTHERA_E2E_ISSUER:?set NAUTHERA_E2E_ISSUER to the issuer URL of a running nauthera-server (e2e/README.md)}"
    : "${NAUTHERA_E2E_CLIENT_ID:?set NAUTHERA_E2E_CLIENT_ID to a public client registered on that server (e2e/README.md)}"
    go test -tags e2e -count=1 -v -timeout 15m ./e2e/... "$@"

# Build every example, as CI does, so an API change cannot break them unseen.
examples:
    go build ./examples/...

# Re-record demo.gif with vhs (https://github.com/charmbracelet/vhs); needs
# vhs, ttyd and ffmpeg. The CLI is examples/nauthera against a local fake
# server (internal/cmd/demoidp), so no account or browser is involved.
demo:
    vhs demo.tape

# Lint with golangci-lint (uses .golangci.yml; formatters included).
lint: golangci-lint-version
    golangci-lint run

# Format the codebase (gofumpt + goimports via golangci-lint v2 formatters).
fmt: golangci-lint-version
    golangci-lint fmt

# Fail if anything is not formatted, without rewriting it.
fmt-check: golangci-lint-version
    golangci-lint fmt --diff

# A golangci-lint other than the pinned one, or one built with an older Go
# than yours, fails here with an install hint instead of a stack trace.
#
# Check that golangci-lint on PATH is the pinned version (scripts/check-golangci-lint.sh).
golangci-lint-version:
    @scripts/check-golangci-lint.sh

# go vet every package, the e2e-tagged ones included.
vet:
    go vet ./...
    go vet -tags e2e ./...

# Tidy and verify the module.
tidy:
    go mod tidy
    go mod verify

# Fail if go.mod or go.sum is not tidy, without rewriting them (CI's tidy job).
tidy-check:
    go mod tidy -diff
    go mod verify

# Scan for known vulnerabilities reachable from this module (govulncheck, pinned above).
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@{{govulncheck_version}} ./...

# golangci-lint recommends its release binaries (brew, the install script) over
# `go install`; either is fine as long as `golangci-lint version` prints the
# pinned version. govulncheck needs no install: `just vuln` runs it pinned.
#
# Install the pinned golangci-lint into $(go env GOPATH)/bin.
install-tools:
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@{{golangci_lint_version}}
    @echo "==> installed golangci-lint {{golangci_lint_version}}; make sure $(go env GOPATH)/bin is on PATH"

# ---- Releasing ----------------------------------------------------------------

# Tag locally first to preview, and delete the tag again if you are not
# releasing yet: `git tag -a v0.3.0 -m v0.3.0 && just release-notes v0.3.0`,
# then `git push origin v0.3.0` or `git tag -d v0.3.0`.
#
# Print the release notes a tag would get (scripts/release-notes.sh).
release-notes tag:
    scripts/release-notes.sh "$1"
