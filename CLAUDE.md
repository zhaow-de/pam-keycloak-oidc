# CLAUDE.md

## Project

`pam-keycloak-oidc` is a single Go binary invoked by `pam_exec` that authenticates a user against an OIDC identity provider (Keycloak) using the OAuth2 resource-owner password credentials grant, then authorizes on a role claim. PAM passes the username in `PAM_USER` and the password on stdin; the process exit status is the entire answer. Config is a TOML file at `<binary path>.tml` derived from `os.Executable()`, so renaming the binary changes which file it reads.

- **Three CLI modes are dispatched purely on `len(os.Args)`** — 3 generates an encoded username, 2 decodes and verifies one, anything else runs the PAM authentication. Adding any flag shifts the count and silently breaks the other two modes.
- **The exit codes are exactly `{0, 1, 2, 7, 11}`** — 0 authenticated and role matched, 2 token-endpoint/OAuth2 failure, 7 authenticated but role mismatch, 11 missing username or password, 1 every `log.Fatal` path. Nothing emits any other code; treat the set as a downstream PAM contract and do not renumber it.
- **A Go panic also exits 2**, colliding with the OAuth2-failure code, and the `// PAM_*` comments beside the `os.Exit` calls name the wrong Linux-PAM constants — under `pam_exec` only zero vs non-zero is consumed, so the numbers are documentation, not behavior.
- **JWT signatures are never verified** — `jwt.Parse`'s error is discarded, the keyfunc returns the token as its own key, and `token.Valid` is deliberately left unchecked; only the `alg` header family (`RS*`/`ES*`/Ed25519) is inspected. That block is load-bearing by accident: real verification would need a JWKS fetch that does not exist here. Do not "simplify" it, and do not "fix" it without an explicit instruction.
- MFA modes are hardcoded (TOTP secret encoded into the username), simple (OTP appended to the password and split off by a hardcoded 6-digit regex in `main()`), and OTP-only.

## Repository layout

Flat `package main` at the **repo root** — no subpackages, no `internal/`, no `cmd/`. Each source file has a `_test.go` sibling in the same package, so tests call unexported functions directly.

- `main.go` / `main_test.go` — CLI dispatch, MFA-mode selection, hand-rolled TOTP, the JWT and role check. The only file that may call `log.Fatal`, `os.Exit` or `panic`.
- `config.go` / `config_test.go` — the TOML `Config`, `ConfigError`, `ErrMissingRequired`, `LoadConfigFromFile`, `LoadConfigFromReader`.
- `oauth2ex.go` / `oauth2ex_test.go` — a tailored fork of `golang.org/x/oauth2`'s password grant, adding the `totp` form parameter and `extra-parameters`.
- `utils.go` / `utils_test.go` — XOR, ASCII85 and Base32 helpers.
- `doc/` — the Hugo site, the only user-facing documentation; `README.md` is a deliberate stub. `doc/themes/hugo-book` is a pinned git submodule and the site will not build without it.
- `.github/workflows/` — `build-go.yml` (fires on `r*` tag pushes) and `hugo.yml` (fires on pushes to `main` that touch `doc/**` or the workflow itself). **Neither is triggered by a pull request or by a push to a feature branch** — only a manual `workflow_dispatch` reaches either from one, which `release.md` forbids for `build-go.yml`.
- `.claude/rules/` — repo-specific rules, and `.claude/skills/` the executable procedures they route to; see Conventions.
- `scripts/` — hooks invoked by `.pre-commit-config.yaml`, nothing else.
- **Ignored root files that look authoritative are not** — `cover.out` is a stale local artifact (regenerate it, never quote it), `out/` is local scratch, `pam-keycloak-oidc*` are build outputs.
- **`CLAUDE.md` and `.claude/` are repo content, not scratch** — `.gitignore` exempts only `.claude/settings.local.json`, so what you write there reaches other clones and reviewers.

## Rules

### 1. Think Before Coding

**Don't assume. Surface tradeoffs. Ask when unclear.**

- State assumptions; mark each *validated / assumed / unknown*.
- Multiple interpretations → present 2–3 with tradeoffs; don't pick silently.
- Name confidence on non-obvious choices (*high / medium / low*).
- Distinguish symptom from root problem.
- Unclear? Stop, name what's confusing, ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked. No "while I'm here."
- No abstractions for single-use code.
- No flexibility / configurability / error handling that wasn't requested.
- 200 lines that could be 50? Rewrite it.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- Remove imports / variables / functions that *your* changes made unused.
- Don't delete pre-existing dead code — mention it instead.

The test: every changed line traces directly to the user's request.

### 4. Define Done by Outcome, Not Output

**"Merged" is not "done." Done is "it works and we can tell."**

- Turn vague tasks into verifiable goals: a failing test that reproduces the bug then passes; tests pass identically before/after a refactor; a real flow completes end-to-end.
- Confirm it's observable: the `log` lines an operator greps, checked by hand as `doc/content/install.md` describes; there is no telemetry here.
- For multi-step work, state a brief plan as `step → verify` lines.

## Tooling

- **The `go.mod` and `build-go.yml` Go versions are pinned to the same exact value** — move the two together in one commit; CI is the only place the six-platform cross-compile happens, so a floor above the CI pin is not caught until a release build fails.
- **A new dependency needs justification** — the project hand-rolls TOTP and forks the OAuth2 password grant rather than adding libraries, and the module graph is deliberately flat (`.claude/rules/go-style.md`).
- **`pre-commit` is the commit gate and the ONLY mechanical check any change gets** — no workflow runs on a pull request, so a hook bypassed with `--no-verify` means the change was never checked at all. Requires `pre-commit` and `golangci-lint` (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`).
- **Released binaries carry no version** — the Makefile's `-X main.Version` / `-X main.Build` ldflags target variables that exist in no `.go` file, so never add a `--version` flag on the assumption that `main.Version` is populated (`.claude/rules/go-style.md`).
- Building needs `go`, `git`, `make` and `find`; building the docs additionally needs Hugo **extended**, at the version `.github/workflows/hugo.yml` pins (`.claude/rules/user-docs.md`).

## Commands

```bash
go build ./...                  # the real compile check
go test ./...                   # the only test gate that exists
go vet ./...                    # clean today; keep it clean
go test -run TestName ./...     # single test
go test -cover ./...            # coverage

make build        # host binary ./pam-keycloak-oidc, with LDFLAGS
make build_all    # cross-compiles darwin/linux/windows × amd64/arm64, without LDFLAGS
make all          # clean + build_all; the only build step the release workflow runs
make clean        # deletes pam-keycloak-oidc.<os>-<arch> only — NOT the plain host binary
make help         # lists the '## '-annotated targets

pre-commit install                        # once per clone; wires the commit gate
pre-commit run -a                         # the full gate, as CI would run it if CI ran it

git submodule update --init --recursive   # required once before any docs build
cd doc && hugo --gc --minify              # mirrors the CI docs build
cd doc && hugo server                     # local preview
```

**Never verify compilation with `make`** — `build_all` wraps `go build` in `$(shell ...)`, so the compiler's exit code is discarded: a file that does not parse still prints `All compiled!` and exits 0 with no binary produced, and CI's `make all` step has the same blind spot. `go build ./...` is the only honest compile check.

## Conventions

- **Open feature PRs against `develop`, never `main`** — GitHub's default branch is `main`, so `gh pr create` needs an explicit `--base develop`; `main` receives code only through a `release/*` merge.
- **Never hand-edit a version string** — every copy of it moves together in one mechanical commit, and the annotated `r<semver>` tag pushed to origin is what fires `build-go.yml`; cut releases with the `release` skill, whose invariants are `.claude/rules/release.md`.
- **The commit gate is `pre-commit run -a`** — run the whole set, never one hook. A run that rewrites files reports **Failed** and leaves the rewrites **unstaged**: re-run until clean, then stage what the hooks rewrote and commit. Never `--no-verify`.
- **Documentation deploys from `main` only** — a docs change sitting on `develop` or a feature branch is not live, and there is no preview deployment.

**Workflow conventions live in `.claude/rules/`** — consult them before branching, committing, opening a PR, or releasing.

- `branch-workflow.md` — branch model and git-flow prefixes: where a change is cut from and where it merges back.
- `commit-messages.md` — conventional-commit types, subject shape and tense, and what must stay out of bodies and trailers.
- `pull-requests.md` — base branch, title, body, and merge strategy.
- `release.md` — version-string, tag and release-asset invariants; the ritual itself is the `release` skill.
- `go-style.md` — package layout, exit discipline, error types, naming, and test conventions.
- `user-docs.md` — Hugo content rules, front matter, and what a config change must update.
- `docs-style.md` — style for CLAUDE.md, the rules files, and markdown.
- `agent-ops.md` — shell and subagent operating lessons.

**Executable procedures live in `.claude/skills/`** — the rules stay the authority on WHEN; load the skill for the HOW rather than assembling the commands yourself.

- `open-pr` — before `gh pr create`, and for writing or fixing a PR title.
- `merge-pr` — merging a reviewed PR, then cleaning up the local and remote branches.
- `release` — cutting a release end to end: bump, merges, tag push, and the published release.
- `dependabot` — working the Dependabot bump PRs: rebase, gate, fix, merge.
