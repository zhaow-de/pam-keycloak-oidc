---
name: open-pr
description: Use when opening a GitHub pull request, or writing or fixing a PR title — load BEFORE running gh pr create.
disable-model-invocation: false
---

# open-pr

## Step 0 — the gate (defense in depth; `.claude/rules/branch-workflow.md` is the authority)

A PR delivers **one completed, nameable component**. Recompute that from the branch name and the diff alone — nothing else in this repo records the decision.

1. **Name the component from the branch name**, then read `git diff --stat develop...HEAD`. The name does not describe the whole diff → the branch is carrying two things; split it, do not open.
2. **The component is complete** — nothing further on this subject is planned for this branch.
3. **The user has explicitly said to open.** A green gate is not the word, and opening early buys no checks at all.

Cannot name the component from the branch name → stop and report the branch ready-or-not instead.

## Step 1 — the local gate

```bash
pre-commit run -a
```

Green before you open (`.claude/rules/agent-ops.md`) — it is the only mechanical check this change will ever get. Do not look to the PR afterwards for confirmation: no workflow triggers on a pull request, so `gh pr checks` reports nothing on it and that is the steady state, not a run still registering.

## Step 2 — the title

```bash
git log develop..HEAD --first-parent --pretty=%s
```

`--first-parent` because a merge of fork work from the `mattil_` remote otherwise lists the fork's own subjects too, and the rewritten merge subject is the branch's own.

One subject → that is the title, **verbatim**. Several → write one subject of the same conventional-commit shape (`.claude/rules/commit-messages.md`) covering the whole component; never concatenate the subjects and never re-prefix one of them.

## Step 3 — open it

```bash
git push -u origin "$(git branch --show-current)"
gh pr create --base develop --title "<subject>" --body ""
```

- Push first — on an unpushed branch `gh pr create` stops to ask where to push, and a non-interactive run fails there.
- `--base develop` on every create; the repo default is `main` (`.claude/rules/pull-requests.md`).
- `--body ""` is the finished body: empty, per `.claude/rules/pull-requests.md`. Pass the flag anyway or gh prompts for body text. There is no PR template here to mirror and no section to fill in.
- Never `--fill`, `--fill-first` or `--fill-verbose` — on a multi-commit branch `--fill` and `--fill-verbose` title the PR with the branch name and fill the body with the commit list, and `--fill-first` titles it with the OLDEST commit's subject; write `--title` and `--body ""` by hand.
