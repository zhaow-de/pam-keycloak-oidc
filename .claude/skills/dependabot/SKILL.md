---
name: dependabot
description: Process Dependabot dependency-update PRs — list, check out, rebase onto develop, run the pre-commit gate, auto-fix gofmt/go.sum/upgrade breakage, push, merge with a merge commit
disable-model-invocation: true
allowed-tools: Bash(git fetch:*), Bash(git checkout:*), Bash(git rebase:*), Bash(git status:*), Bash(git stash:*), Bash(git push:*), Bash(git add:*), Bash(git commit:*), Bash(git log:*), Bash(git branch:*), Bash(git rev-parse:*), Bash(git stash list:*), Bash(gh pr:*), Bash(pre-commit run:*), Bash(go build:*), Bash(go test:*), Bash(go vet:*), Bash(go mod tidy), Bash(go env:*), Bash(gofmt:*), Bash(golangci-lint:*), Bash(echo:*), Read, Glob, Grep, Edit, Write, AskUserQuestion
---

# Dependabot PR management

Process Dependabot dependency-update PRs in this repo: check out, rebase onto `develop`, run the local gate, auto-fix routine breakage, push, merge.

## Context

- Current branch: !`git branch --show-current`
- Working tree: !`git status --porcelain || echo "clean"`
- Open PRs (Dependabot ones have a `dependabot/` head branch): !`gh pr list --json number,title,headRefName,baseRefName -q '.[] | "#\(.number) \(.baseRefName) <- \(.headRefName): \(.title)"'`

## Repo specifics

- **Every ecosystem in `.github/dependabot.yml` sets `target-branch: develop`**, so a Dependabot PR bases on `develop`, never on `main` — `main` advances only through the release ritual (`.claude/rules/branch-workflow.md`). A Dependabot PR based on `main` means that entry drifted: stop and report.
- **Three ecosystems, `open-pull-requests-limit: 1` each**, so the queue is at most three PRs: `gomod` (touches `go.mod` + `go.sum`), `github-actions` (`.github/workflows/*`), `pre-commit` (`.pre-commit-config.yaml`).
- **`github-actions` and `pre-commit` arrive GROUPED** — one PR carries several bumps and its title names the group instead of a version pair, so read the PR body's per-bump table before classifying it.
- **No workflow runs on a pull request** — `build-go.yml` fires on `r*` tags, `hugo.yml` on pushes to `main`. A Dependabot PR therefore has no checks at all, and an empty `statusCheckRollup` is its normal final state, not "checks not registered yet". Never wait on or poll `gh pr checks` / `statusCheckRollup`.
- **`pre-commit run -a` is the entire verification** (`.claude/rules/agent-ops.md`), so merging is gated on having seen that gate pass on the rebased branch in this session — nothing downstream will catch what it misses.
- Go code is one flat `package main` at the repo root: run every command from the repo root, and verify over `./...`.

## Workflow

### Phase 1 — Setup & discovery

1. **Save current state** — stash uncommitted changes (including untracked) so Phase 3 can restore them:
   ```bash
   git stash push -m "dependabot-skill-temp" --include-untracked 2>/dev/null || true
   ```

2. **Read the original branch and write the literal name into the plan** — shell state does not survive to the next Bash call, so Phase 3 cannot read a variable set here:
   ```bash
   git branch --show-current
   ```

3. **Sort** the Dependabot PRs by priority: minor/patch first, major last. Classify a single-bump PR from the `from <X> to <Y>` in its title; classify a grouped PR from its body's bump table, and call the whole group major if any member is a major bump. Oldest first within a class — the longest-pending PR needs the most rebasing.

4. **Report the plan**: the PRs in processing order, each with its base branch noted (must be `develop`). Then wait — `.claude/rules/pull-requests.md` gates every merge on the user's explicit word, so get it for this queue before Phase 2 merges anything.

### Phase 2 — Process each PR (loop)

#### 2a. Check out + rebase onto develop

```bash
git fetch origin
gh pr checkout <number>
git rebase origin/develop
```

If the rebase conflicts:
- `go.mod` / `go.sum` — take the PR side, then reconcile with `go mod tidy` before continuing the rebase.
- Anything else (a `.go` file, a workflow, `.pre-commit-config.yaml`) → **stop and ask** via AskUserQuestion with the conflict diff.

> **Note:** pushing the rebased branch makes Dependabot stop managing this PR. That is fine — the skill merges it immediately after.

#### 2b. Local validation

```bash
pre-commit run -a
```

That is the full gate: gofmt, `go vet ./...`, `go build ./...`, `go test ./...`, golangci-lint, plus the hygiene hooks. When it fails, attack the failing hook directly instead of re-running the whole set:

```bash
gofmt -l .
go vet ./...
go build ./...
go test ./...
PATH="$(go env GOPATH)/bin:$PATH" golangci-lint run --config .golangci.yml ./...
```

`golangci-lint` is not on `PATH` — it lives in `$(go env GOPATH)/bin` and the hook exports that itself, so run it with the prefix above or as `pre-commit run golangci-lint -a`.

#### 2c. Auto-fix (if validation fails)

| Failure | Auto-action | Max attempts |
|---|---|---|
| gofmt (hook reports files were modified) | The hook already rewrote them in the working tree — re-run the gate, then carry the named paths into the fix commit below. | 1 |
| `go build` on a missing or mismatched `go.sum` entry | `go mod tidy`, then re-run `go build ./...`. | 1 |
| `go build` / `go test` broken by the upgrade | Read the error and patch it only if it is obviously upgrade-shaped (renamed symbol, changed signature, moved package). Re-run `go build ./...`, then `go test ./...`. | 3 |
| golangci-lint | `PATH="$(go env GOPATH)/bin:$PATH" golangci-lint run --config .golangci.yml --fix ./...`, re-run, then patch what remains by hand if obvious. | 3 |

A break that is not obviously upgrade-shaped, or one still failing at the cap → **stop and ask**. Don't silently keep retrying, and never quiet a linter by editing `.golangci.yml`.

Commit the fixes under `.claude/rules/commit-messages.md` — read it first; it owns the subject's shape, the body, the forbidden trailers, and explicit-path staging:

```bash
git add <the exact files 2c edited>
git commit -m "fix: adjusted <symbol> for the <package> upgrade"
```

The commit re-runs the hooks. If gofmt rewrites a file during it, re-stage and re-commit — never `--no-verify`, which would leave the change with no check at all.

#### 2d. Push + merge

Push only when the branch actually moved — a no-op rebase with no fix commit needs no push:

```bash
git rev-parse HEAD "origin/$(git branch --show-current)"
```

Same SHA → go straight to the merge. Different → the rebase or a 2c fix commit moved the branch, so push with a lease:

```bash
git push --force-with-lease origin "$(git branch --show-current)"
```

Merge only after 2b passed on this branch in this session, and only on the user's word from Phase 1. There is no check to consult (see "Repo specifics"), so that local gate is the only evidence the bump is safe:

```bash
gh pr merge <number> --merge --delete-branch
```

Merge commit, never `--squash` or `--rebase` (`.claude/rules/pull-requests.md`). Pass no `-t`/`-b`: the default message keeps Dependabot's own `build(deps): bump …` title, already the tool-written form `.claude/rules/commit-messages.md` expects.

### Phase 3 — Cleanup

```bash
git checkout <the branch name recorded in Phase 1>
ref=$(git stash list | grep -F "dependabot-skill-temp" | head -1 | cut -d: -f1)
[ -n "$ref" ] && git stash pop "$ref"
```

Pop only this skill's own entry: on a clean-tree run Phase 1 saved nothing, so a bare `git stash pop` would drop the user's pre-existing stash onto the branch.

Report a summary:
- Merged PRs, with number and package.
- Skipped PRs, with the reason (major bump awaiting review, wrong base branch, declined).
- Failed PRs, with the error (conflict, persistent gate failure).

## User escalation triggers

Pause for the user only when:

1. **A rebase conflict outside `go.mod`/`go.sum`.**
2. **A failure that survives the cap** in §2c.
3. **A major-version bump** — surface the breaking changes from the dependency's own release notes (linked in the PR body) and ask before merging.
4. **A gate failure the bump cannot explain** — already red on `develop` before the rebase. Surface it; do not patch around it inside a dependency PR.
5. **A PR based on anything but `develop`** — likely a `target-branch` drift in `.github/dependabot.yml`.
6. **Any doubt the bump should land at all** — most Dependabot PRs here were closed rather than merged, so declining is a normal outcome, but never close one yourself: surface it and ask.

## Key commands reference

```bash
# Open PRs with base and head branch (Dependabot heads start with dependabot/)
gh pr list --json number,title,headRefName,baseRefName

# One PR in full — the body carries a grouped PR's per-bump table
gh pr view <number>

# What the bump actually changes
gh pr diff <number>

# Check out a PR's head branch by number
gh pr checkout <number>

# Re-run one gate hook by id: go-fmt, go-vet, go-build, go-test, golangci-lint, staged-kind
pre-commit run <hook-id> -a

# Merge-commit and delete the head branch, local and remote
gh pr merge <number> --merge --delete-branch
```

## Notes

- Bound every network-touching `git`/`gh` call with the Bash tool's `timeout` parameter and run it as its own step (`.claude/rules/agent-ops.md`) — `timeout(1)` is not installed on this machine, so a shell `timeout` prefix fails with "command not found".
- Prefer separate `go …` / `git …` lines over composite `(cd X && Y) && Z` commands; every command runs from the repo root.
