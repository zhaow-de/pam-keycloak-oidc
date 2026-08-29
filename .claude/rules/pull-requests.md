# Pull request convention

- **WHEN to open is `branch-workflow.md`'s PR gate** — one complete, nameable component, on the user's explicit word.
- **HOW to open a PR, or to write or fix its title, is the `open-pr` skill** (`.claude/skills/open-pr/SKILL.md`); **HOW to merge one and clean the clone up afterwards is the `merge-pr` skill** (`.claude/skills/merge-pr/SKILL.md`) — load the skill instead of assembling the commands from these bullets.
- **Pass `--base develop` on every `gh pr create`** — the repo's default branch is `main`, so an unqualified create opens against the wrong base. No PR you open targets `main` — the release merge into `main` is a plain merge, not a PR (`release.md`).
- **PR title = the branch's commit subject, verbatim** — copy it, never re-prefix or re-word it; on a multi-commit branch write one subject of that same shape (`commit-messages.md`) covering the whole component.
- **Leave the PR body empty** — no summary, no test plan, no checklist; a bare issue URL is the only body text a maintainer PR here has ever carried.
- **Never append the `🤖 Generated with Claude Code` footer, or any other tool-generated trailer** — no PR in this repo has one.
- **Merge only on the user's word, and always with a merge commit** (`gh pr merge --merge`): it produces `Merge pull request #NN from zhaow-de/<branch>` with the PR title as the body, and the repo auto-deletes the head branch. **Never squash or rebase** — the squashed PRs in older history are an abandoned pattern, not an exemplar.
