---
name: merge-pr
description: Use when a reviewed pull request is ready to merge and the local clone needs cleanup afterward — e.g. "merge PR #33 and clean up". Merge-commit only (never squash or rebase), and the local commit gate has to be green first.
disable-model-invocation: false
allowed-tools: Bash(git status:*), Bash(git checkout:*), Bash(git pull:*), Bash(git branch:*), Bash(git ls-remote:*), Bash(git push:*), Bash(git fetch:*), Bash(gh pr:*), Bash(pre-commit run:*), Bash(python3:*)
---

# merge-pr

## Overview

Merging a PR is a shared, hard-to-reverse action. **Gate it on verification first, then clean up local state safely.** Never merge past a failed gate; never touch a dirty worktree. If a gate fails, report exactly what is wrong and ask the user to resolve it manually — do not work around it, do not proceed.

Two gates, both mandatory: the GitHub-side fields (Step 2) and `pre-commit run -a` (Step 3). Nothing on GitHub checks the code here, so a clean Step 2 says only that the merge is mechanically possible.

Every PR merges with a merge commit — `.claude/rules/pull-requests.md` owns the method and the title convention.

## When to use

- The user confirms a PR is reviewed/ready and asks to merge it and/or clean up local branches.
- Finishing a Claude-authored PR after the user's review.

**Not for:** opening a PR (the PR gate in `.claude/rules/branch-workflow.md`); advancing `main` (release-only, a plain merge and never a PR — `.claude/rules/release.md`); a Dependabot bump, which `.claude/skills/dependabot/SKILL.md` takes end to end, its merge included.

## Step 1 — Identify the PR

```bash
gh pr view <number> --json number,headRefName,baseRefName,state,mergeable,mergeStateStatus,reviewDecision,isDraft,statusCheckRollup
```

(Omit `<number>` to use the current branch's PR.) Record `number`, `headRefName` and `baseRefName`; the rest are the Step 2 gate fields.

Base correctness (`develop`, never `main`) is the gate's first check — a fork PR can target `main`, so a wrong base is not hypothetical.

## Step 2 — The GitHub gate (STOP if ANY fails)

GitHub has no single ready-to-merge field; readiness is spread across several. Pipe the Step 1 JSON through this evaluator — it prints `GATE PASSED` or lists every failing gate:

```bash
gh pr view <number> --json number,headRefName,baseRefName,state,mergeable,mergeStateStatus,reviewDecision,isDraft,statusCheckRollup \
  | python3 -c '
import sys, json
d = json.load(sys.stdin)
fails = []
rollup = d.get("statusCheckRollup") or []
if d.get("baseRefName") != "develop":
    fails.append("base branch is " + repr(d.get("baseRefName")) + ", not develop (feature PRs never merge to main)")
if d.get("state") != "OPEN":
    fails.append("state is " + repr(d.get("state")) + ", expected OPEN")
if d.get("isDraft"):
    fails.append("PR is a draft")
m = d.get("mergeable")
if m == "CONFLICTING":
    fails.append("mergeable=CONFLICTING — resolve the conflicts on the branch first")
elif m != "MERGEABLE":
    fails.append("mergeable=" + repr(m) + " — GitHub is still computing; re-run in a moment, never merge on UNKNOWN")
if d.get("mergeStateStatus") == "BLOCKED":
    fails.append("mergeStateStatus=BLOCKED — develop is protected now; read the protection before merging")
if d.get("reviewDecision") == "CHANGES_REQUESTED":
    fails.append("reviewDecision=CHANGES_REQUESTED (a reviewer requested changes)")
# An EMPTY rollup is the normal case here and must NOT fail: no workflow triggers on a pull request.
_DONE = ("SUCCESS", "NEUTRAL", "SKIPPED")
_BAD = ("FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "STARTUP_FAILURE")
_state = lambda c: (c.get("conclusion") or c.get("state") or "").upper()
bad = [c for c in rollup if _state(c) in _BAD]
if bad:
    fails.append(str(len(bad)) + " CI check(s) failing")
pending = [c for c in rollup if _state(c) not in _DONE + _BAD]
if pending:
    fails.append(str(len(pending)) + " CI check(s) still running — wait and re-run")
if fails:
    print("GATE FAILED:")
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("GATE PASSED on GitHub — merge only after the local gate in Step 3")
'
```

What each gate covers:

1. **`baseRefName == "develop"`** — every feature, fix, dependency and doc PR lands on `develop`; `main` advances only through the release merge.
2. **`state == "OPEN"`** and **`isDraft == false`** — not already merged/closed, not a draft. A merged PR also reports `mergeable=UNKNOWN`, so both lines fire and the state line is the one to read.
3. **`mergeable == "MERGEABLE"`** — GitHub computed a clean merge. `CONFLICTING` is a hard stop; `UNKNOWN` means GitHub is still computing — wait a few seconds and re-run (the gate refuses it).
4. **`mergeStateStatus != "BLOCKED"`** — neither `develop` nor `main` is protected here, so `BLOCKED` means protection was added since; stop and read it rather than merging past it. `CLEAN`, `UNSTABLE`, `BEHIND` and `HAS_HOOKS` are all fine for a merge commit (being behind `develop` is reconciled by the merge).
5. **`reviewDecision != "CHANGES_REQUESTED"`** — reviews are not required, so this field is normally empty and the user's go-ahead (why this skill was invoked) is the approval.
6. **CI checks, when there are any** — an **empty `statusCheckRollup` is expected**, because no workflow here triggers on `pull_request`, so a PR never reports a check and an empty rollup is not a wait. A non-empty rollup means a workflow was added since: then a failing or an unfinished check blocks the merge.

**If any gate fails:** report which one and why, ask the user to resolve it (rebase/update the branch, retarget the base, fix the check), then **STOP**. Do not merge.

## Step 3 — The local gate (STOP unless it is green)

`pre-commit run -a` is the only mechanical check this repo has (`.claude/rules/agent-ops.md`) — nothing on GitHub ever compiled, vetted or tested the head branch.

A past run leaves no exit status anywhere, so **ask the user to confirm they ran `pre-commit run -a` on the PR head and it passed**. Unconfirmed is a failed gate — never merge on the assumption it was run.

If they cannot confirm, run it yourself — only on a clean worktree:

```bash
git status --porcelain
git fetch origin
git checkout <headRefName>
git pull --ff-only
pre-commit run -a
```

A hook that **rewrites** a file (gofmt, end-of-file-fixer) leaves the fix uncommitted and outside the PR: **STOP** and tell the user the branch needs another commit. Never merge on `SKIP=` or `--no-verify` output.

## Step 4 — Merge

```bash
gh pr merge <number> --merge
```

`--merge` creates a merge commit — this skill's only method, never `--squash`, never `--rebase` — and the explicit flag makes the command non-interactive.

Never pass `-t`/`-b`: `gh` writes the merge commit itself, and a hand-written subject or body is the one way a forbidden trailer or footer reaches it (`.claude/rules/commit-messages.md`).

Omit `--delete-branch`: the repo deletes the remote head branch on merge by itself, while `-d` would also delete the local branch after switching the clone to a branch of its own choosing. Steps 5–7 do the local side deterministically.

## Step 5 — Sync develop (STOP on a dirty worktree)

```bash
git status --porcelain
```

If that prints **anything**, the worktree is dirty: **STOP**. Tell the user to stash/commit first — the PR is already merged, so local cleanup is only deferred; do not switch branches. Otherwise:

```bash
git checkout develop
git pull --ff-only
```

If the pull is not a fast-forward, STOP and report — do not create a merge commit locally.

## Step 6 — Delete the local branch

```bash
git branch -d <headRefName>
```

You switched to `develop` in Step 5, so you are not on the branch being deleted, and the merge commit from Step 4 makes it fully integrated — `-d` succeeds.

`error: branch ... not found` means the head was never checked out locally (a Dependabot branch, for one): expected, not a failure. If `-d` ever errors "not fully merged" **and** the PR shows merged **and** the remote branch is gone, the work IS integrated and `git branch -D <headRefName>` is then safe.

## Step 7 — Confirm the remote branch is gone

```bash
git ls-remote --heads origin <headRefName>
```

Empty output = deleted, which is the repo's own auto-delete doing its job. If it still prints a ref, **warn** the user, then delete it:

```bash
git push origin --delete <headRefName>
```

## Step 8 — Fetch all remotes + prune

```bash
git fetch --all --prune
```

This clone has the `mattil_` fork alongside `origin`, so `--all` is not the same as fetching `origin`; `--prune` drops remote-tracking refs whose upstream branch is gone.

## Report

Summarize: PR merged (or which gate stopped you), local gate confirmed or run, develop synced (or dirty-worktree stop), local + remote branch deleted, prune done.

## Common mistakes

| Mistake | Fix |
|---|---|
| Merging and letting GitHub reject it if it is not ready | Run Steps 2 and 3 FIRST; stop and ask on any failure |
| Reading an empty `statusCheckRollup` as "CI has not registered yet" | Nothing triggers on a pull request here — empty is normal, never a reason to wait |
| Taking a green Step 2 as evidence the code builds | Step 2 only proves the merge is possible; `pre-commit run -a` is the only check |
| Treating `mergeable=UNKNOWN` as ready | GitHub is still computing — wait and re-run |
| Squashing or rebasing the merge | Always `--merge` — `.claude/rules/pull-requests.md` |
| `gh pr merge -d` for convenience | Omit it; Steps 5–7 delete the branch and leave the clone on `develop` |
| `git checkout develop` on a dirty worktree | `git status --porcelain` first; stop if dirty |
| `git remote prune origin` only | `git fetch --all --prune` — `mattil_` is a second remote |
