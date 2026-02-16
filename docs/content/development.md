---
weight: 90
title: 'Development environment'
---

# Development environment

## Prerequisites

- [Go](https://go.dev/dl/) 1.21+
- [Hugo](https://gohugo.io/installation/) (for documentation)
- [GoReleaser](https://goreleaser.com/install/) (for packaging)

## Project structure

```
.
├── src/                      # Go source code
│   ├── *.go                  # Main application code
│   ├── go.mod / go.sum       # Go modules
│   └── packaging/            # Packaging scripts and configs
├── docs/                     # Hugo documentation site
├── Makefile                  # Build automation
└── .goreleaser.yaml         # Release configuration
```

## Line endings (CRLF / LF)

The repository enforces **LF** line endings via `.gitattributes` to prevent issues when
developing on Windows and deploying to Linux (e.g., shell scripts with `\r\n` break on the server).

Git handles the conversion automatically on checkout and commit, so normally you don't need
to do anything. If you see CRLF warnings or existing files have wrong endings after adding
`.gitattributes` to an existing clone, run:

```shell
# Re-normalize all tracked files to match .gitattributes
git config core.autocrlf input
git add --renormalize .
git commit -m "Normalize line endings"

# Verify - the "i/" column should show "lf" for text files
git ls-files --eol
```

If `--renormalize` does not help (rare), convert manually with `dos2unix`:

```shell
# Install: sudo dnf install dos2unix  (or apt install dos2unix)
dos2unix $(git ls-files --eol | grep 'i/crlf' | awk '{print $4}')
```

## Building

```shell
# Build for local architecture
make build

# Build for Linux amd64 only
make linux_build

# Build for all platforms (darwin, linux, windows × amd64, arm64)
make build_all
```

The binary is built from `src/` and placed in the project root.
It embeds version and build info via `-ldflags`:

```shell
./pam-keycloak-oidc --version
# pam-keycloak-oidc 1.5.2 (build abc1234...)
```

## Testing

```shell
# Run all tests (from project root)
make test

# Or manually from src/ directory
cd src
go test ./... -v

# Run tests with race detector
cd src
go test -race ./... -v

# Run a specific test file / function
cd src
go test -v -run TestNewTokenRequest_NoDoubleEncoding
```

## Static analysis

```shell
# Vet - reports suspicious constructs
go vet ./...

# Optional: staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
staticcheck ./...
```

## Pre-commit hook (optional, local only)

A simple Git pre-commit hook that runs `gofmt` and `go vet` before each commit.
This is **local to your machine** and does not affect other contributors.

Create `.git/hooks/pre-commit`:

```shell
#!/bin/sh
# Pre-commit hook: format + vet
cd src || exit 1

UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then
    echo "gofmt: formatting files:"
    echo "$UNFORMATTED"
    gofmt -w .
    echo "$UNFORMATTED" | xargs git add
fi

go vet ./... || exit 1

# git commit --amend --no-edit
```

Then make it executable:

```shell
chmod +x .git/hooks/pre-commit
```

{{% hint info %}}
This hook lives in `.git/hooks/` which is **not tracked by Git**. Each developer
must set it up manually after cloning. The CI pipeline runs `golangci-lint` on
every tagged build regardless, so the hook is a convenience, not a requirement.
{{% /hint %}}

## Packaging (RPM + DEB)

[GoReleaser](https://goreleaser.com/) is used to produce RPM and DEB packages as well as tar.gz archives.
Configuration is in `.goreleaser.yaml`.

```shell
# Local snapshot build (no publishing, no git tag required)
make snapshot
# - or equivalently —
goreleaser release --snapshot --clean
```

This creates packages under `dist/`:

```
dist/
├── pam-keycloak-oidc_linux_amd64.tar.gz   # binary + config template + health check
├── pam-keycloak-oidc_linux_arm64.tar.gz
├── pam-keycloak-oidc_<version>_amd64.rpm
├── pam-keycloak-oidc_<version>_arm64.rpm
├── pam-keycloak-oidc_<version>_amd64.deb
├── pam-keycloak-oidc_<version>_arm64.deb
└── pam-keycloak-oidc_checksums.txt
```

The tar.gz archives include:

- `pam-keycloak-oidc` - the binary
- `src/packaging/pam-keycloak-oidc.tml.example` - reference config template
- `src/packaging/check-keycloak-health.sh` - health check script for PAM fast-fail
- `src/packaging/test_token.sh` - test script

The RPM/DEB packages additionally run a post-install script (`src/packaging/postinstall.sh`) that configures SELinux context.

## Documentation

The outline of this documentation is too complex to fit into a single README.md.

[Hugo](https://gohugo.io) is used to render the static website hosted at Github Pages, and [Hugo Book](https://themes.gohugo.io/themes/hugo-book/) is chosen as the theme.
A Github Actions workflow is configured to automatically build and publish the changes merged to the `main` branch.

Please follow the [instructions](https://gohugo.io/installation/) to setup the local development environment.

```shell
# Preview documentation locally
cd docs
hugo server

# Build static site
cd docs
hugo --minify
```

## Version bumping

Version is tracked in three places (kept in sync by `.bumpversion.cfg`):

- `Makefile` - `VERSION=x.y.z`
- `README.md` - `Current version: **x.y.z**`
- `docs/content/_index.md` - `Current version: **x.y.z**`

### Installation

**Fedora / RHEL / CentOS:**
```shell
sudo dnf install bumpversion
```

**Other distributions:**
```shell
# Using pip (user install)
pip install --user bump2version

# Or using pipx (isolated environment, recommended)
pipx install bump2version
```

### Usage

```shell
# Test without making changes
bumpversion --dry-run --verbose patch

# Bump version
bumpversion patch   # 1.5.2 → 1.5.3
bumpversion minor   # 1.5.2 → 1.6.0
bumpversion major   # 1.5.2 → 2.0.0
```

The tool automatically:

- Updates version in all configured files
- Creates a git commit (if `commit = True` in config)
- Requires clean working directory (use `--allow-dirty` to override)
