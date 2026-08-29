---
name: release
description: Cut a release — reconcile tags, bump the version on a release/<x.y.z> branch, merge into main and back into develop, push the r<version> tag, and confirm build-go.yml published the GitHub Release
disable-model-invocation: false
allowed-tools: Bash(git status:*), Bash(git log:*), Bash(git branch:*), Bash(git checkout:*), Bash(git tag:*), Bash(git rev-parse:*), Bash(git ls-remote:*), Bash(git fetch:*), Bash(git pull:*), Bash(git merge:*), Bash(git push:*), Bash(cz:*), Bash(pre-commit run:*), Bash(gh auth status), Bash(gh run list:*), Bash(gh run view:*), Bash(gh run rerun:*), Bash(gh release view:*)
---

Cuts a release with `cz` on a `release/<x.y.z>` branch, merges it into `main` and back into `develop`, and pushes the annotated `r<version>` tag.
The tag push fires `.github/workflows/build-go.yml`, which builds the six binaries and publishes the GitHub Release itself — this skill never creates a release, it confirms the workflow did.
`.claude/rules/release.md` owns the ritual's rules; this file is the executable form of them.

## Context

- Current branch: !`git branch --show-current`
- Current version: !`cz version --project`
- Prerequisites: !`which cz && which gh && which pre-commit && echo "all found" || echo "MISSING tools"`

## Instructions

1. **Verify prerequisites** from the context above.

   Stop and report if any tool is missing, if the current branch is not `develop`, or if the tree is dirty:

   ```bash
   git status --porcelain --untracked-files=no
   ```

   This must print nothing — `cz bump` commits with `git commit -a` (step 6) and sweeps every unstaged edit to a tracked file into the tagged commit.
   `--untracked-files=no` because `git commit -a` cannot sweep an untracked file into the tagged commit, so an untracked stray must never block a release.
   Confirm `gh auth status` succeeds; on a 401, ask the user to run `gh auth refresh -h github.com` first.

2. **Reconcile local tags against origin before anything else**:

   ```bash
   git tag -l 'r*'
   git ls-remote --tags origin 'r*'
   ```

   Every tag in the first list must appear in the second; the remote's peeled `refs/tags/rX^{}` lines are the same annotated tags, not extra ones.
   A tag that exists only locally means the newest published release is older than the version in the tree, and bumping on top of it skips that version permanently.
   Stop and report the unpublished tags — the user decides whether to push one or delete it. Do not bump.

3. **Sync `develop` and check `main` for drift**:

   ```bash
   git pull origin develop
   git fetch origin main
   git log develop..origin/main --oneline
   ```

   Commits listed by the last command are on `main` but not on `develop` — a past release or hotfix that was never merged back. Releasing on top of that drift re-introduces its conflicts in the version files.

   If it lists anything, show the commits and back-merge before continuing — `develop` is not protected, so this is a plain merge and a plain push, no PR:

   ```bash
   git merge origin/main --no-edit
   git push origin develop
   ```

   If the merge conflicts, do not push: report each conflicted file and stop.

4. **Learn the next version** — bare version, no `r`, no `v`:

   ```bash
   cz bump --get-next
   ```

   Run it on its own and read the output: it is `<x.y.z>` for every remaining step.

   **Cut the release branch**, naming `develop` explicitly:

   ```bash
   git checkout -b release/<x.y.z> develop
   ```

5. **Run the commit gate on the release branch, BEFORE bumping**:

   ```bash
   pre-commit run -a
   ```

   This is the only thing that compiles, vets, lints and tests the release — the workflow's `make all` cannot fail (`.claude/rules/agent-ops.md`), so nothing downstream catches a broken build.
   If the `golangci-lint` hook errors because the binary is absent, install it with `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest` and re-run.
   If a hook rewrites a file, the tree is dirty again: commit that fix as its own typed commit (`.claude/rules/commit-messages.md`) or discard it, then re-run until the gate is green on a clean tree.

6. **Bump**:

   ```bash
   cz bump --yes
   ```

   This rewrites the `version_files`, commits `build(repo): bumped version A → B`, and creates the annotated `r<x.y.z>` tag on that commit.

7. **Verify the bump actually rewrote every version file.**

   `cz` silently skips a `version_files` entry whose line no longer contains the previous version, so a file that drifted in a past release keeps the old version and nothing reports it.

   ```bash
   NEW_VERSION=$(cz version --project)
   README_VERSION=$(grep -oE 'Current version: \*\*[0-9]+\.[0-9]+\.[0-9]+\*\*' README.md | head -1 | sed -E 's/.*\*\*(.*)\*\*/\1/')
   DOC_VERSION=$(grep -oE 'Current version: \*\*[0-9]+\.[0-9]+\.[0-9]+\*\*' doc/content/_index.md | head -1 | sed -E 's/.*\*\*(.*)\*\*/\1/')
   MAKE_VERSION=$(grep -E '^VERSION=' Makefile | head -1 | sed -E 's/^VERSION=//')

   if [ "$README_VERSION" != "$NEW_VERSION" ] || [ "$DOC_VERSION" != "$NEW_VERSION" ] || [ "$MAKE_VERSION" != "$NEW_VERSION" ]; then
       echo "ERROR: cz bump skipped one or more version_files"
       echo "  cz says:              $NEW_VERSION"
       echo "  README.md:            $README_VERSION"
       echo "  doc/content/_index.md: $DOC_VERSION"
       echo "  Makefile:             $MAKE_VERSION"
       exit 1
   fi

   git tag --points-at HEAD
   ```

   `git tag --points-at HEAD` must print `r$NEW_VERSION` — that tag is the only thing that triggers a release.
   On any mismatch, stop and report: nothing is pushed yet, so the release branch can be fixed or deleted.

8. **Merge into `main`, then merge `main` back into `develop`** — direct merges, no PR:

   ```bash
   git checkout main
   git pull --ff-only origin main
   git merge --no-ff --no-edit release/<x.y.z>
   git checkout develop
   git merge --no-edit main
   ```

   Step 3 updated `origin/main` only, so bring local `main` up to it first — merging onto a stale `main` pushes fine but drops the earlier release merges out of its first-parent history.
   `--no-ff` on the `main` side keeps the merge commit the history has always carried; the back-merge fast-forwards when it can.
   Stop and report on a conflict — nothing is pushed yet.

9. **Push `main` and `develop` first, the tag LAST** — each as its own step:

   ```bash
   git push origin main
   git push origin develop
   git push origin r<x.y.z>
   ```

   The tag push is what fires `build-go.yml`. Pushing it before the branches would publish a release built from a ref the branches do not yet carry.

10. **Confirm the workflow published the release. Do NOT run `gh release create`** — `build-go.yml` creates the GitHub Release from the tag with `generate_release_notes: true` and uploads the six binaries; a manual release collides with it.

    ```bash
    gh run list --workflow build-go.yml --branch r<x.y.z> --limit 1 --json databaseId,status,conclusion,url
    ```

    Re-run that one command as its own Bash call, with the tool's `timeout` parameter, until `status` is `completed` — never a shell loop that sleeps (`.claude/rules/agent-ops.md`).
    An empty result means the tag push has not registered yet; re-check rather than concluding the workflow did not fire.

    On `conclusion: success`, read the published release:

    ```bash
    gh release view r<x.y.z> --json url,assets -q '.url, (.assets|length)'
    ```

    Six assets are expected. Report and stop on any other conclusion, on fewer assets, or if the release is missing.
    Recover a failed build with `gh run rerun <databaseId> --failed`, which re-runs against the tag ref; `.claude/rules/release.md` says why a `workflow_dispatch` must never be used instead.

    The `main` push also redeploys the docs site, because the bump rewrites `doc/content/_index.md` and `hugo.yml` filters pushes on `doc/**`. Confirm that run too:

    ```bash
    gh run list --workflow hugo.yml --branch main --limit 1 --json headSha,status,conclusion,url
    ```

    Its `headSha` must equal the merge commit now on `main` — compare against `git rev-parse main`. Every push to `main` is a release, so without that comparison the previous release's run reads as this one's and the docs get reported as published when nothing fired (`.claude/rules/user-docs.md`).

11. **Local cleanup**:

    ```bash
    git branch -d release/<x.y.z>
    git fetch --all --prune
    ```

    `-d` succeeds because the branch is merged into both `main` and `develop`.

12. **Report** the new version, the tag, the release URL from step 10, the docs-deploy result, and that `main` and `develop` are in lock-step.

## Common mistakes

| Mistake | Instead |
| --- | --- |
| `gh release create` after the tag push | Let `build-go.yml` publish; poll `gh run list` and read `gh release view` |
| `git push --tags`, or pushing the tag before the branches | `git push origin main`, then `develop`, then `git push origin r<x.y.z>` |
| Opening a PR for the release merge or the back-merge | Plain `git merge` + `git push`; neither branch is protected here |
| A plain `git merge` into `main` that fast-forwards | `git merge --no-ff --no-edit release/<x.y.z>` |
| `make all` or `make build_all` as the build check | `pre-commit run -a`, before the bump |
| Bumping with a dirty tree | `git status --porcelain --untracked-files=no` empty first — `cz bump` commits with `git commit -a` |

## Notes

- Stop and report on any failure; do not improvise past a step that did not do what it says.
- Do not use composite commands — they force a permission request.
- You are already in the repo folder — do not `cd` first.
