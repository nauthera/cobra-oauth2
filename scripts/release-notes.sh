#!/usr/bin/env bash
# The release notes for a tag: the conventional-commit subjects since the
# previous release, grouped by type, as Markdown on stdout. Within a group the
# entries are sorted by scope, unscoped last, so one area's changes read
# together. A `!` after the type or a `BREAKING CHANGE:` footer lists the
# commit under "Breaking changes", first, since that is what someone upgrading
# needs before anything else. Maintenance (chore, ci, test, refactor, build,
# style, and anything not conventional) and dependency updates (scope `deps`)
# are folded into <details> blocks: they concern whoever works on the
# repository, not whoever imports the module.
#
# A pull request lands as a merge commit titled with the pull request's title
# (the repository's merge setting), which CI holds to Conventional Commits, and
# that one entry stands for every commit it brought in, which are left out. A
# merge whose subject is not conventional (main merged into a branch) stands for
# nothing, so what it brought in is listed on its own. A squash merge is a single
# conventional commit and needs no special case. The previous release is the
# newest vX.Y.Z tag behind this one; candidates (-rc.N) are passed over, so a
# candidate's notes cover everything the release would ship.
#
#   scripts/release-notes.sh <tag>      (or: just release-notes <tag>)
#
# Run it on an unpushed local tag to preview the notes. With GITHUB_REPOSITORY
# set (and GITHUB_SERVER_URL, as Actions sets both), the notes end with a link
# comparing the two tags. Kept in step with nauthera-server's copy, so both
# projects' release notes read the same. Portable to bash 3.2 (macOS).
set -euo pipefail

tag=${1:?usage: scripts/release-notes.sh <tag>}
if ! git rev-parse -q --verify "$tag^{commit}" >/dev/null; then
	echo "release-notes: $tag names no commit" >&2
	exit 2
fi

# A conventional subject's head: type, optional (scope), optional !, colon.
# Bracket expressions rather than backslashes, so awk reads it as bash does.
cc='^[a-z]+([(][^)]*[)])?!?: '

prev=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude 'v*-*' "$tag^" 2>/dev/null || true)
range=$tag
if [ -n "$prev" ]; then range="$prev..$tag"; fi

skips=$(mktemp)
trap 'rm -f "$skips"' EXIT
git log --merges --format='%P%x09%s' "$range" | while IFS=$'\t' read -r parents subject; do
	[[ $subject =~ $cc ]] || continue
	read -r first second _ <<<"$parents"
	git rev-list "$first..$second"
done >"$skips"

# The C locale makes the scope order byte order in every awk.
notes=$(git log --format='%H%x1f%h%x1f%P%x1f%s%x1f%b%x1e' "$range" | LC_ALL=C awk -v skips="$skips" -v cc="$cc" '
	BEGIN {
		while ((getline sha < skips) > 0) skip[sha] = 1
		RS = "\036"; FS = "\037"
		split("feat fix perf revert docs", t, " ")
		for (i in t) typed[t[i]] = 1
		n = split("breaking feat fix perf revert docs other deps", order, " ")
		title["breaking"] = "Breaking changes"; title["feat"] = "Features"; title["fix"] = "Bug fixes"
		title["perf"] = "Performance"; title["revert"] = "Reverts"; title["docs"] = "Documentation"
		title["other"] = "Maintenance"; title["deps"] = "Dependencies"
		folded["other"] = 1; folded["deps"] = 1
	}
	{ sub(/^\n+/, "") }
	$1 == "" || ($1 in skip) { next }
	{
		subject = $4; scope = ""
		if (match(subject, cc)) {
			head = substr(subject, 1, RLENGTH); text = substr(subject, RLENGTH + 1)
			sub(/: +$/, "", head); sub(/^ +/, "", text)
			bang = sub(/!$/, "", head)
			if (match(head, /[(].*[)]$/)) {
				scope = substr(head, RSTART + 1, RLENGTH - 2)
				head = substr(head, 1, RSTART - 1)
			}
			section = (head in typed) ? head : "other"
			if (scope == "deps") { section = "deps"; scope = "" }
			if (bang || $5 ~ /(^|\n)BREAKING[ -]CHANGE: /) section = "breaking"
		} else if (index($3, " ")) {
			next
		} else {
			text = subject; section = "other"
		}
		entry = "- " (scope == "" ? "" : "**" scope ":** ") text
		if (text !~ /[(]#[0-9]+[)]$/) entry = entry " (" $2 ")"
		# A stable insertion sort, which every awk can run: history order
		# (newest first) is kept within a scope.
		key = (scope == "" ? "1" : "0" scope)
		k = ++count[section]
		while (k > 1 && sortkey[section, k - 1] > key) {
			sortkey[section, k] = sortkey[section, k - 1]; line[section, k] = line[section, k - 1]; k--
		}
		sortkey[section, k] = key; line[section, k] = entry
	}
	END {
		for (i = 1; i <= n; i++) {
			s = order[i]
			if (!(s in count)) continue
			if (shown++) printf "\n"
			if (s in folded) printf "<details>\n<summary>%s (%d)</summary>\n\n", title[s], count[s]
			else printf "### %s\n\n", title[s]
			for (k = 1; k <= count[s]; k++) print line[s, k]
			if (s in folded) print "\n</details>"
		}
	}')

if [ -n "$prev" ]; then echo "## Changes since $prev"; else echo "## Changes"; fi
echo
if [ -n "$notes" ]; then printf '%s\n' "$notes"; else echo 'No changes.'; fi
if [ -n "$prev" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
	printf '\n**Full changelog:** %s/%s/compare/%s...%s\n' \
		"${GITHUB_SERVER_URL:-https://github.com}" "$GITHUB_REPOSITORY" "$prev" "$tag"
fi
