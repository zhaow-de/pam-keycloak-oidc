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
