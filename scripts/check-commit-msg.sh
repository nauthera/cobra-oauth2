#!/usr/bin/env bash
# Check that commit messages follow Conventional Commits
# (https://www.conventionalcommits.org/en/v1.0.0/), the shape
# scripts/release-notes.sh groups a release's changes by.
#
#   scripts/check-commit-msg.sh <file>             a commit message file, as the
#                                                  commit-msg hook passes it
#   scripts/check-commit-msg.sh --subject <text>   one subject line (a PR title)
#   scripts/check-commit-msg.sh --range <a>..<b>   every non-merge commit in a range
#
# The subject is `type(scope)!: description`. The scope and the `!` are
# optional, the scope is lowercase and may list several areas
# (`fix(device,pkce): ...`). The types are the ones release-notes.sh knows; the
# scopes are not checked here, CONTRIBUTING.md lists the usual ones.
#
# Subjects git writes itself are let through: `Merge ...` and `Revert "..."`.
# `fixup!`, `squash!` and `amend!` are fine in a local commit, since they are
# meant to be squashed away, but refused in --subject and --range, which check
# what is about to land.
#
# Exit status: 0 when every message passes, 1 when one does not, 2 on misuse.
# Portable to bash 3.2 (macOS).
set -euo pipefail

types='feat|fix|perf|revert|docs|refactor|test|build|ci|chore|style'
scope_word='[a-z0-9][a-z0-9._/-]*'
header_re="^(${types})(\\(${scope_word}(, ?${scope_word})*\\))?!?: [^ ]"
git_generated_re='^(Merge |Revert ")'
autosquash_re='^(fixup|squash|amend)! '
# A hard limit, generous enough for a Dependabot subject naming a long module
# path. Aim for 72 or fewer.
max_header=100

usage() {
	echo "usage: scripts/check-commit-msg.sh <file> | --subject <text> | --range <a>..<b>" >&2
	exit 2
}

failures=0

# fail <where> <header> <reason>
fail() {
	failures=$((failures + 1))
	{
		printf 'commit message %s does not follow Conventional Commits: %s\n' "$1" "$3"
		printf '    %s\n' "$2"
	} >&2
}

# check_header <where> <header> <allow_autosquash>
check_header() {
	local where=$1 header=$2 allow_autosquash=$3

	if [ -z "$header" ]; then
		fail "$where" "(empty)" "the subject line is empty"
		return
	fi
	if [[ $header =~ $git_generated_re ]]; then
		return
	fi
	if [[ $header =~ $autosquash_re ]]; then
		if [ "$allow_autosquash" = yes ]; then return; fi
		fail "$where" "$header" "squash it into the commit it fixes before merging (git rebase -i --autosquash)"
		return
	fi
	if ! [[ $header =~ $header_re ]]; then
		fail "$where" "$header" "expected 'type(scope): description' with type one of ${types//|/, }"
		return
	fi
	if [ "${#header}" -gt "$max_header" ]; then
		fail "$where" "$header" "the subject is ${#header} characters long, keep it to ${max_header} (ideally 72)"
		return
	fi
	case $header in
	*.)
		fail "$where" "$header" "drop the trailing period"
		return
		;;
	esac
}

# check_body <where> <message>: the line after the subject is blank.
check_body() {
	local where=$1 message=$2 second
	second=$(printf '%s\n' "$message" | sed -n '2p')
	if [ -n "$second" ]; then
		fail "$where" "$second" "leave a blank line between the subject and the body"
	fi
}

# strip_message: drop git's comment lines and everything below the scissors
# line that `git commit -v` adds, then trailing whitespace.
strip_message() {
	local comment
	comment=$(git config --get core.commentChar 2>/dev/null || true)
	case $comment in
	'' | auto) comment='#' ;;
	esac
	awk -v c="$comment" '
		index($0, c " ------------------------ >8 ------------------------") == 1 { exit }
		index($0, c) == 1 { next }
		{ sub(/[ \t\r]+$/, ""); print }
	'
}

[ $# -ge 1 ] || usage
mode="file"

case $1 in
--subject)
	[ $# -eq 2 ] || usage
	mode=subject
	subject=$(printf '%s' "$2" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	check_header "subject" "$subject" no
	;;
--range)
	[ $# -eq 2 ] || usage
	mode=range
	if ! commits=$(git rev-list --no-merges --reverse "$2"); then
		echo "check-commit-msg: git cannot list $2" >&2
		exit 2
	fi
	for sha in $commits; do
		message=$(git log -1 --format=%B "$sha" | sed -e 's/[[:space:]]*$//')
		header=$(printf '%s\n' "$message" | sed -n '1p')
		check_header "$(git rev-parse --short "$sha")" "$header" no
		check_body "$(git rev-parse --short "$sha")" "$message"
	done
	;;
-*)
	usage
	;;
*)
	[ $# -eq 1 ] || usage
	[ -r "$1" ] || {
		echo "check-commit-msg: cannot read $1" >&2
		exit 2
	}
	message=$(strip_message <"$1" | sed -e '/./,$!d')
	header=$(printf '%s\n' "$message" | sed -n '1p')
	check_header "subject" "$header" yes
	if [ -n "$header" ] && ! [[ $header =~ $git_generated_re ]]; then
		check_body "body" "$message"
	fi
	;;
esac

if [ "$failures" -gt 0 ]; then
	cat >&2 <<'EOF'

Examples:
    feat(device): poll with the interval the server asks for
    fix(storage)!: key tokens by issuer and client id
    docs: explain the e2e setup

See CONTRIBUTING.md, "Conventional Commits".
EOF
	if [ "$mode" = file ]; then
		# shellcheck disable=SC2016 # the backticks are literal
		echo 'Your message is kept in .git/COMMIT_EDITMSG; `git commit -e -F .git/COMMIT_EDITMSG` reopens it.' >&2
	fi
	exit 1
fi
