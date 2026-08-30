# Release

Releases are cut with **commitizen** (`cz`, configured in `.cz.toml`). See `branch-workflow.md` for the branch model this sits on.

- **HOW to cut one is the `release` skill** (`.claude/skills/release/SKILL.md`) — tag reconciliation, the `release/<x.y.z>` branch, the gate, the bump, the two merges, the pushes, and confirming `build-go.yml` published; load it rather than reassembling the steps.
- **Never hand-edit a version string.** `cz bump` rewrites `.cz.toml`, `README.md`, `docs/content/_index.md` and `Makefile` in one commit; editing one and missing another silently desynchronises the docs from the build.
- **A new file carrying the version joins `version_files` in `.cz.toml` in the same change that introduces it** — otherwise it is left behind at the next bump and nothing reports it.
- **Tag format differs per track** — the 1.x line is `r<version>`, and from 2.0.0 the tag is the bare version. `build-go.yml` triggers on `r*` and on `[0-9]*`, so both publish; a `v`-prefixed tag still matches neither and publishes nothing without raising an error.
- **Tags are annotated** (`annotated_tag = true`), matching every existing release tag.
- **The tag sits on the bump commit, not on the main-side merge** — that is where `cz bump` puts it, and it is an ancestor of the merge, so the published artifact is unaffected. Every tag predating this convention sits on a merge commit instead; do not "restore" that by hand-moving tags.
- **Push `main` and `develop` first, the tag last** — the tag push is what fires `build-go.yml`, and that workflow creates the GitHub release *before* uploading any asset, so a failed build leaves a public release carrying no binaries.
- **Bump size is derived from the commit types since the last tag** — the map is `[tool.commitizen.customize]` in `.cz.toml`; a type outside it does not bump at all, so check there before inventing a type (`commit-messages.md` owns which types are legal).
- **A release branch may carry release-preparation work as well as the bump** — tooling, agent-configuration and doc changes readied for that release land on it directly, because routing them through `develop` first would only delay the same merge. Anything that changes the binary's behaviour still goes through a `feature/*` PR into `develop` (`branch-workflow.md`).
- **`cz bump` does not check the tree — make `git status --untracked-files=no` empty before bumping** — it commits with `git commit -a`, sweeping every unstaged edit to a tracked file into the tagged `build(repo)` commit; untracked files are safe, which is why the flag is there.
- **Never trigger `build-go.yml` with `workflow_dispatch`** — the release is tagged `github.ref_name`, which on a branch is the branch name, so a dispatch publishes a release tagged after the branch. Only a tag push releases.
- **Release asset names are a public contract and differ from the build outputs** — the darwin and windows binaries upload under different names (`macOS-intel`, `macOS-arm64`, `pam-keycloak-oidc-amd64.exe`, `pam-keycloak-oidc-arm64.exe`), which are the download URLs every published release already carries. They are set by the staging step in `build-go.yml` that copies each build output to its published name; renaming there breaks every download script written against a release.

## Two release tracks

While 2.x is in development, two tracks publish to the same releases page: the stable 1.x line from `main`, and 2.x prereleases from `develop`.

- **`.cz.toml` is per-branch, and that is the whole mechanism** — `develop`'s copy carries `tag_format = "$version"` and the 2.x version, `main`'s carries `r$version` and the 1.x version. Neither track can bump the other.
- **Cut `support/1.x` from `main` BEFORE the 2.0.0 merge lands there** — that merge replaces `main`'s `.cz.toml` with the 2.x one, and a maintenance branch cut afterwards would tag the 1.x line with bare 2.x-shaped versions. Cut it first and it keeps `r$version` and 1.4.0.
- **A prerelease is tagged, not branched** — on `develop`, `cz bump --yes --prerelease alpha` produces `2.0.0-a0`, `2.0.0-a1`, then `cz bump --yes` produces `2.0.0`. Push `develop`, then the tag; there is no `release/*` branch and no merge to `main` for an alpha.
- **`prerelease` is derived from the tag, not passed by hand** — `build-go.yml` sets it from a hyphen in `github.ref_name`, so `2.0.0-a0` publishes as a prerelease and never becomes the "Latest release" that the install docs point readers at. Keep `version_scheme = "semver"`: PEP 440's `2.0.0a0` has no hyphen, and GoReleaser rejects it as a version.
- **The docs site publishes both versions from one artifact, newest at the root** — `hugo.yml` serves the newest version at `/` so a visitor who names no version gets current documentation, and gives each older line a `/vN/` prefix. Pages replaces the whole site on each deploy, so a build that skipped a version would delete it; the workflow always builds every version, on a push to either branch.
