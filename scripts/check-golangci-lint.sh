#!/usr/bin/env bash
# Check that the golangci-lint on PATH is the version this repository pins
# (golangci_lint_version in the justfile) and was built with a Go at least as
# new as the local toolchain. An older build panics on newer standard library
# sources ("file requires newer Go version"), which reads like a bug in the
# code under lint rather than a stale tool.
#
#   scripts/check-golangci-lint.sh
#
# Exit status: 0 when the binary fits, 1 with an install hint when it does not.
# Portable to bash 3.2 (macOS).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
want="$(sed -n 's/^golangci_lint_version *:= *"v\{0,1\}\([^"]*\)".*/\1/p' "$root/justfile")"
hint="run 'just install-tools' and make sure \$(go env GOPATH)/bin comes first on PATH"

if ! command -v golangci-lint >/dev/null 2>&1; then
    echo "golangci-lint not found; $hint" >&2
    exit 1
fi
out="$(golangci-lint version 2>&1 || true)"
have="$(printf '%s\n' "$out" | sed -n 's/.*has version v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -n 1)"
if [ "$have" != "$want" ]; then
    echo "golangci-lint is ${have:-of unknown version} ($(command -v golangci-lint)), this repository pins v$want; $hint" >&2
    exit 1
fi

# "built with go1.26.2": compare major.minor with the local toolchain.
built="$(printf '%s\n' "$out" | sed -n 's/.*built with go\([0-9]*\.[0-9]*\).*/\1/p' | head -n 1)"
local_go="$(go env GOVERSION 2>/dev/null | sed -n 's/^go\([0-9]*\.[0-9]*\).*/\1/p')"
if [ -n "$built" ] && [ -n "$local_go" ]; then
    b_major="${built%%.*}" b_minor="${built#*.}"
    l_major="${local_go%%.*}" l_minor="${local_go#*.}"
    if [ "$b_major" -lt "$l_major" ] || { [ "$b_major" -eq "$l_major" ] && [ "$b_minor" -lt "$l_minor" ]; }; then
        echo "golangci-lint v$have was built with go$built, older than the local go$local_go, and cannot load its standard library; $hint" >&2
        exit 1
    fi
fi
