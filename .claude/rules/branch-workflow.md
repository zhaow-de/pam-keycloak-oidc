# Branch workflow

- **`develop` is the integration branch** — every feature, fix, dependency bump and doc change is cut from `develop` and its PR goes back into `develop`. The one exception is release-preparation work, which may land directly on the release branch (`release.md`).
- **`main` is release-only** — advance it only by merging a `release/<x.y.z>` branch, and only through the ritual in `release.md`, which the `release` skill (`.claude/skills/release/SKILL.md`) executes end to end. Never branch off `main`, never commit to `main` directly, never open a feature PR into `main`.
- **Name `develop` explicitly when cutting a branch** — `git checkout -b feature/<topic> develop`; a fresh clone lands on `main`, so an unqualified checkout inherits the wrong base.
- **Name branches `feature/<kebab-case-topic>` and `release/<x.y.z>`** — the release branch carries the bare version, no `r` and no `v`; the `r` prefix belongs to the tag alone.
- **Ask before starting a `hotfix/` or `support/` branch** — neither has ever been used here, so an urgent fix has no established route out of `main`.
- **One PR delivers ONE component, and the component must be nameable from the branch name alone** — its implementation, the fixes found along the way, and the doc updates it forces all land in that same PR; a multi-commit branch is correct. The **PR-open gate**, recomputable from the branch name and the diff so a freshly compacted context re-derives the decision instead of improvising it:
  1. **Name the component from the branch name.** The name does not describe the whole diff → the branch is carrying two things; split it, do not open.
  2. **The component is complete** — nothing further on this subject is planned for this branch.
  3. **The word.** Open only when the user explicitly says so — finish the branch, run the local gate in `agent-ops.md`, report it ready, and wait. No workflow runs on pull requests, so opening early buys no checks at all.
- **Both failure modes are equally wrong.** *Micro-PR*: a green commit is never by itself a reason to open a PR — a one-file PR on a subject that will be touched again strips the reviewer of context. *Omnibus PR*: a second subject is never a reason to reuse an open branch — two subjects ⇒ two branches, however small each is.
- **Fold a trivial, already-verified one-liner into the related open PR** as an extra commit instead of cutting a second branch; ask when unsure it qualifies.
- Titles, body, and merge strategy are in `pull-requests.md`; merging a PR and cleaning the clone up afterwards is the `merge-pr` skill (`.claude/skills/merge-pr/SKILL.md`).
