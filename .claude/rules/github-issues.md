# GitHub issue workflow

Enforced in review. Applies to every task that changes this repo, by a person or an agent.
Work is tracked as issues in **nauthera/cobra-oauth2**. No issue, no work; no link, no
merge. The sections run in the order a task does.

## 0. Constants

| Thing | Value |
| --- | --- |
| Repo | `nauthera/cobra-oauth2`. Every issue for this library is filed here. |
| Org | `nauthera`. Issue types and issue fields are the organization's, shared with nauthera-server. |
| Project | None. There is no project board, Status, Team, Estimate or Iteration for this repo. |

| Issue field | Id | Options |
| --- | --- | --- |
| Priority | `IFSS_kgDOAePjRg` | Urgent `IFSSO_kgDOA062Rg` · High `IFSSO_kgDOA062Rw` · Medium `IFSSO_kgDOA062SA` · Low `IFSSO_kgDOA062SQ` |
| Effort | `IFSS_kgDOAePjSQ` | High `IFSSO_kgDOA062Sg` · Medium `IFSSO_kgDOA062Sw` · Low `IFSSO_kgDOA062TA` |
| Start date, Target date | `IFD_kgDOAePjRw`, `IFD_kgDOAePjSA` | unused; leave them empty |

Issue fields are set only through GraphQL (§ 3.6). If a session refuses `gh api graphql`
(some answer HTTP 403), create the issue with REST or `gh issue create` and tell the user
which fields still need setting by hand.

## 1. Before you start: does an issue already exist?

First action of every task. Search **open and closed**, one term at a time (GitHub ANDs
space-separated words, so a two-word guess silently returns nothing):

```bash
gh issue list --repo nauthera/cobra-oauth2 --state all --search "dpop"
gh issue list --repo nauthera/cobra-oauth2 --state all --search "nonce OR dpop"
```

- **An open issue covers it**: use it; check its type, labels, Priority and Effort (§ 3).
- **A closed issue covers it**: it regressed or the ask differs. Say which, and propose
  reopening or a follow-up.
- **Nothing covers it**: § 2.

**A bug in nauthera-server** (or any other server) is never filed from here, and never in
nauthera-server by an agent. Tell the user what the server does, what the specification
says (document and section), and how to reproduce it, and leave filing it there to a human.
If the library needs a workaround meanwhile, that is an issue here (`providers`, § 3.3).

## 2. Nothing covers it: size it, then ask

- One **`Task`** for one PR. An **`Epic`** with sub-issues when the work needs several PRs
  or spans several areas (a new grant with its option, command flag and docs).
- **Never open an issue unprompted.** Confirmation to do the work is not confirmation to
  file an issue. Propose it and wait for a yes:

  > No open issue covers this. I'd open **"Honour the DPoP nonce on revocation"**: type
  > `Task`, labels `spec:dpop, rfc-conformance`, Priority Medium, Effort Low. Open it?

## 3. Opening the issue

### 3.1 Check the taxonomy; never invent a label or type

```bash
gh label list --repo nauthera/cobra-oauth2 --limit 100
gh api orgs/nauthera/issue-types --jq '.[].name'
gh api graphql -f query='{organization(login:"nauthera"){issueFields(first:25){nodes{
  __typename
  ... on IssueFieldSingleSelect{id name options{id name}}
  ... on IssueFieldDate{id name}
}}}}'
```

If a label you need does not exist, ask before creating one.

### 3.2 Issue type (every issue carries one)

| Type | Use for |
| --- | --- |
| `Task` | The default: one piece of work, one PR. |
| `Bug` | The library breaks its own documented behaviour. |
| `Story` | Value described from an importer's or a CLI user's side. |
| `Spike` | Research with a written answer as the deliverable. |
| `Epic` | A capability that holds sub-issues (§ 4). |

An RFC gap is a `Task`, not a `Bug`: the contract was never met, rather than broken.
`Initiative` is the organization's top level and is not used here.

### 3.3 Labels

Pick one from each row that applies:

- **Area**: `storage` (`pkg/storage`), `cmd` (the cobra commands and their output),
  `providers` (presets, quirks, provider fixtures), `examples`, `e2e` (the live tests),
  `ci`, `documentation`, `dependencies`. `go` is Dependabot's and not used on issues.
- **Spec family** (protocol work): `spec:oauth-core` (RFC 6749, 6750, 8252, 9126, 9207,
  9700), `spec:pkce` (RFC 7636), `spec:token` (RFC 7009, 7662, 8693, 8707),
  `spec:jose` (ID tokens, JWKS, RFC 7638), `spec:dpop` (RFC 9449), `spec:device`
  (RFC 8628), `spec:discovery` (RFC 8414, OpenID Connect Discovery), `spec:client-auth`
  (RFC 7523, 8705, client secrets), `spec:oidc-session` (RP-Initiated Logout).
- **Nature**: `rfc-conformance` (a gap against a specification), `enhancement`, `bug`,
  `security` (the gap has a security consequence, not merely touches tokens).

Never file a vulnerability as a public issue: [SECURITY.md](../../SECURITY.md) says how to
report one privately.

### 3.4 Body: lean, in this format

```markdown
The device flow keeps polling at the old interval after a slow_down that carries no
interval, so a strict server answers every later poll with slow_down again and the login
never completes.

**Spec:** RFC 8628 §3.5.

### Done when
- [ ] After slow_down the interval grows by 5 seconds and stays grown.

### Automated tests
- Integration: against `oauthtest` with a slow_down script, the waits the fake clock
  records grow by 5 seconds and never shrink.
```

- The opening paragraph (2 to 4 lines) states the observable gap and who it hurts:
  behaviour, not the patch, no file names.
- `**Spec:**` is mandatory whenever a standard applies: document and section, never pasted.
- `### Done when`: one to three observable outcomes.
- `### Automated tests` is mandatory on every `Task`, one bullet per test, naming its tier
  and the behaviour it pins: `Unit:` (a pure rule, table-driven), `Integration:` (a flow
  against `internal/oauthtest` or a fixture), `Fuzz:` (a parser of untrusted input),
  `End-to-end:` (`e2e/` against nauthera-server). A negative case (no leak, single use, a
  refusal) is a `Unit:` or `Integration:` bullet. If a change cannot be tested, say why.
  Epics carry none; their tasks do.

### 3.5 Create it

`gh issue create` bypasses `.github/ISSUE_TEMPLATE/`, so the format is on you. Write the
body to a temporary file outside the repository, never inline with `--body`, which
mangles backticks and newlines:

```bash
gh issue create --repo nauthera/cobra-oauth2 \
  --title "Grow the device polling interval after every slow_down" \
  --type Task \
  --label rfc-conformance --label spec:device \
  --body-file "$BODY"   # BODY=$(mktemp), written with a heredoc
# add --parent <epic#> for a sub-issue
```

### 3.6 Set Priority and Effort

Both belong on every issue, epics included. One mutation sets both, keyed by the issue's
node id:

```bash
ISSUE=12
ISSUE_ID=$(gh issue view $ISSUE --repo nauthera/cobra-oauth2 --json id --jq .id)
gh api graphql -f query='
mutation {
  setIssueFieldValue(input: {
    issueId: "'"$ISSUE_ID"'"
    issueFields: [
      {fieldId: "IFSS_kgDOAePjRg", singleSelectOptionId: "IFSSO_kgDOA062SA"}   # Priority = Medium
      {fieldId: "IFSS_kgDOAePjSQ", singleSelectOptionId: "IFSSO_kgDOA062TA"}   # Effort   = Low
    ]
  }) { issue { number } }
}'
```

Read them back:

```bash
gh api graphql -f query='{repository(owner:"nauthera",name:"cobra-oauth2"){
  issue(number:12){issueType{name} issueFieldValues(first:10){nodes{
    ... on IssueFieldSingleSelectValue{value field{... on IssueFieldSingleSelect{name}}}}}}}}'
```

| Field | Value |
| --- | --- |
| Priority | `Urgent`: broken on `main` or a security hole. `High`: blocks other work or a release. `Medium`: the default. `Low`: no date attached. |
| Effort | How much is unknown. `Low`: the approach is obvious. `Medium`: several files or some investigation first. `High`: the approach itself is the question. |

## 4. Epics

Open one `Epic` (the capability in 2 to 4 lines, the spec family, what "complete" means; no
`### Automated tests`), then each child as a `Task` with `--parent <epic#>`, shippable in
one PR. Set Priority and Effort on each. Attach to an existing epic rather than open a
near-duplicate; reparent with `gh issue edit <n> --parent <epic#>`.

## 5. Starting work

Assign yourself (`gh issue edit <n> --repo nauthera/cobra-oauth2 --add-assignee @me`) and
branch off `main` (CONTRIBUTING.md § 8).

## 6. The PR links the issue

The PR body's `## What & why` section (`.github/PULL_REQUEST_TEMPLATE.md`) carries
`Closes #N` for each issue it resolves, or `Refs #N` for one it only advances. A keyword in
a commit message or a comment does not close anything. Close an epic yourself once its
sub-issues are done. The PR title is a Conventional Commit (CLAUDE.md).

## 7. Checklist

- [ ] Searched open and closed issues here, one term at a time.
- [ ] An issue covers the work, existing or opened with the user's approval; a server bug
      was reported to the user, not filed.
- [ ] Type, labels and (for a sub-issue) parent set; Priority and Effort set.
- [ ] The body cites the spec section and has `### Automated tests`.
- [ ] Assigned to me; the PR body says `Closes #N`, and the tests the issue named exist.
