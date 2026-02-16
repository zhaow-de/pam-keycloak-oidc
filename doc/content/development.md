---
weight: 90
title: "Development environment"
---

# Development environment

## Prerequisites

- [Go](https://go.dev/dl/) 1.21+
- [Hugo](https://gohugo.io/installation/) (for documentation)
- [GoReleaser](https://goreleaser.com/install/) (for packaging)

## Building

```shell
# Build for local architecture
make build

# Build for Linux amd64 only
make linux_build

# Build for all platforms (darwin, linux, windows × amd64, arm64)
make build_all
```

The binary embeds version and build info via `-ldflags`:

```shell
./pam-keycloak-oidc --version
# pam-keycloak-oidc 1.5.2 (build abc1234...)
```

## Testing

```shell
# Run all tests
go test ./... -v

# Run tests with race detector
go test -race ./... -v

# Run a specific test file / function
go test -v -run TestNewTokenRequest_NoDoubleEncoding
```

## Static analysis

```shell
# Vet — reports suspicious constructs
go vet ./...

# Optional: staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
staticcheck ./...
```

## Packaging (RPM + DEB)

[GoReleaser](https://goreleaser.com/) is used to produce RPM and DEB packages as well as tar.gz archives.
Configuration is in `goreleaser.yaml`.

```shell
# Local snapshot build (no publishing, no git tag required)
make snapshot
# — or equivalently —
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
- `pam-keycloak-oidc` — the binary
- `packaging/pam-keycloak-oidc.tml.example` — reference config template
- `packaging/check-keycloak-health.sh` — health check script for PAM fast-fail

The RPM/DEB packages additionally run a post-install script (`packaging/postinstall.sh`) that configures SELinux context.

## Documentation

The outline of this documentation is too complex to fit into a single README.md.

[Hugo](https://gohugo.io) is used to render the static website hosted at Github Pages, and [Hugo Book](https://themes.gohugo.io/themes/hugo-book/) is chosen as the theme.
A Github Actions workflow is configured to automatically build and publish the changes merged to the `main` branch.

Please follow the [instructions](https://gohugo.io/installation/) to setup the local development environment.

```shell
# Preview documentation locally
cd doc
hugo server

# Build static site
cd doc
hugo --minify
```

## Version bumping

Version is tracked in three places (kept in sync by `.bumpsemver.cfg`):

- `Makefile` — `VERSION=x.y.z`
- `README.md` — `Current version: **x.y.z**`
- `doc/content/_index.md` — `Current version: **x.y.z**`

To bump:

```shell
# pip install bumpsemver
bumpsemver patch   # 1.5.2 → 1.5.3
bumpsemver minor   # 1.5.2 → 1.6.0
bumpsemver major   # 1.5.2 → 2.0.0
```
