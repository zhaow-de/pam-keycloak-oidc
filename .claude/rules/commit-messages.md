# Commit message convention

[Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): `<type>(<scope>): <subject>` — the types this repo uses are `feat` `fix` `test` `refactor` `doc` `chore` `build` `claude`.

- **Write the subject in PAST tense, lowercase after the type, no trailing period, under ~75 characters** — "added", "extracted", "enabled"; the spec's imperative default reads wrong beside every commit in this history.
- **Spell the documentation type `doc:`, never `docs:`** — the singular is this repo's spelling, and normalizing it to the spec splits the type in two.
- **Type any change to `CLAUDE.md` or `.claude/` as `claude:`, never `doc:`** — `doc:` is reserved for `docs/content/` and `README.md`, and `.cz.toml` bumps on both.
- **Never use `ci:`** — workflow, Makefile and pipeline changes have gone under `chore:` here.
- **Never write `build:` or a scope by hand** — the only two forms are `build(repo)` for version bumps (subject `bumped version A → B`, U+2192 arrow, never `->`) and `build(deps)` for dependency bumps, both tool-written; the release ritual is `release.md`, and a Dependabot PR is processed end to end by the `dependabot` skill (`.claude/skills/dependabot/SKILL.md`), whose merge keeps Dependabot's own `build(deps)` subject.
- **Leave the body empty** — exactly one hand-written body exists in the whole repo, so a multi-paragraph summary with bullet lists marks the commit as foreign.
- **Link an issue by full URL, never `Fixes #N`** — the closing keyword auto-closes the issue, a behavior this repo has never exercised.
- **Never add a `Co-Authored-By:` trailer** — Claude Code appends one by default and it must be stripped; no maintainer commit here carries one.
- **Never mix `CLAUDE.md`/`.claude/` with other files in one commit** — the `staged-kind` hook refuses it; `SKIP=staged-kind` is the deliberate exception.
- **Stage by explicit path — never `git add -A` or `git add -u`** — a blanket add sweeps whatever else is dirty into a typed commit, and mixes the kinds the `staged-kind` hook then refuses.
- **`CLAUDE.md` and `.claude/` are tracked — stage and commit your edits to them** — the agent conventions are meant to survive a fresh clone; `.claude/settings.local.json` is the only ignored piece.
- **Merging fork work from the `mattil_` remote: rewrite the merge subject into a conventional-commit line and keep git's auto-generated `Merge commit '<sha>'` body** — the rewritten subject is the only record of what the merge delivered.
