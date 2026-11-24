# Agent instructions

The project's rules for every contributor, person or agent, are in [CLAUDE.md](CLAUDE.md)
and the files it links under [`.claude/rules/`](.claude/rules/). They apply to any coding
agent, whatever its tool reads by default; this file only points there so that each rule
has one home.

Read before changing code:

- [CLAUDE.md](CLAUDE.md): what the library is, its independence from nauthera-server, the
  security invariants, public API care, commands and commits.
- [`.claude/rules/code-economy.md`](.claude/rules/code-economy.md): search before you
  write, one owner per rule, comments that say what is true now.
- [`.claude/rules/go-testing.md`](.claude/rules/go-testing.md): every test parallel, the
  helpers and fakes that exist and when to use each, fixtures, fuzz targets, no network.
- [`.claude/rules/rfc-compliance.md`](.claude/rules/rfc-compliance.md): how protocol
  behaviour is added or changed, provider quirks, and the standards matrix.
- [`.claude/rules/github-issues.md`](.claude/rules/github-issues.md): the issue workflow.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to build, test and ship.
