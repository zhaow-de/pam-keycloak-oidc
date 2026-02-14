# pam-keycloak-oidc

Current version: **1.5.1**

A PAM module connecting to [Keycloak](https://www.keycloak.org/) for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or precisely, TOTP (Time-based One-time Password), is supported.

This is a fork of [zhaow-de/pam-keycloak-oidc](https://github.com/zhaow-de/pam-keycloak-oidc) with the following additions:

- JWKS-based JWT signature verification (using [keyfunc/v3](https://github.com/MicahParks/keyfunc))
- Token issuer and audience validation
- Token expiration enforcement
- `--version` and `--help` CLI flags
- RPM and DEB packages with SELinux post-install configuration
- Updated documentation for Keycloak 26.x
- Comprehensive deployment guide ([KC_CONFIG.md](KC_CONFIG.md))

Visit https://revalew.github.io/pam-keycloak-oidc/ for detailed documentation.

## Installation

### RPM (RHEL / Oracle Linux / Rocky / Alma)

**Latest version:**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -i pam-keycloak-oidc_amd64.rpm
```

**Specific version:**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/download/v1.5.1/pam-keycloak-oidc_1.5.1_amd64.rpm

sudo rpm -i pam-keycloak-oidc_1.5.1_amd64.rpm
```

**Upgrade (preserves your `.tml` config):**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -U pam-keycloak-oidc_amd64.rpm
```

### DEB (Debian / Ubuntu)

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.deb

sudo dpkg -i pam-keycloak-oidc_amd64.deb
```

### Binary (manual)

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_linux_amd64.tar.gz

tar -xf pam-keycloak-oidc_linux_amd64.tar.gz

sudo mkdir -p /opt/pam-keycloak-oidc

sudo mv pam-keycloak-oidc /opt/pam-keycloak-oidc/

sudo chmod 755 /opt/pam-keycloak-oidc/pam-keycloak-oidc
```

> **Note:** `arm64` packages are also available - replace `amd64` with `arm64` in the URLs above.

### What the package installs

```bash
rpm -ql pam-keycloak-oidc
```

| File                                                   | Purpose                                   |
| ------------------------------------------------------ | ----------------------------------------- |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc`             | PAM binary                                |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`         | Config (edit this - preserved on upgrade) |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml.example` | Reference config template                 |
| `/opt/pam-keycloak-oidc/check-keycloak-health.sh`      | Health check script for PAM fast-fail     |

After installation, edit the `.tml` config and health check script, then configure PAM and SSHD.
See [KC_CONFIG.md](KC_CONFIG.md) for a complete deployment guide.

## Credits

- Original project by [zhaow-de](https://github.com/zhaow-de/pam-keycloak-oidc)
- Thanks @MattiL for the [alternative signing method](https://github.com/MattiL/pam-keycloak-oidc/tree/ecc) support
- Thanks @willstott101 for adding [arm64 support](https://github.com/willstott101/pam-keycloak-oidc/commit/554076f40a597ab0ec24a1578e624b55d2686111) in the build pipeline
