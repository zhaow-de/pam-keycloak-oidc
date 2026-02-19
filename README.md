# pam-keycloak-oidc

Current version: **1.5.4**

A PAM module connecting to [Keycloak](https://www.keycloak.org/) for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or precisely, TOTP (Time-based One-time Password), is supported.

Visit [GitHub Pages](https://revalew.github.io/pam-keycloak-oidc/) for detailed documentation.

<br/>
<br/>

This is a fork of [zhaow-de/pam-keycloak-oidc](https://github.com/zhaow-de/pam-keycloak-oidc) with the following additions:

- JWKS-based JWT signature verification (using [keyfunc/v3](https://github.com/MicahParks/keyfunc))

- Token issuer and audience validation

- Token expiration enforcement

- Configurable OTP length and character class (`otp-require`, `otp-length`, `otp-class`)

- Fix for special characters in client secret causing auth failures ([upstream #10](https://github.com/zhaow-de/pam-keycloak-oidc/issues/10))

- Code refactored into modules (`config.go`, `utils.go`, `jwks.go`, `oauth2ex.go`)

- `--version` and `--help` CLI flags

- RPM and DEB packages with SELinux post-install configuration

- Updated documentation for Keycloak 26.x, display manager compatibility (GDM, SDDM/KDE, LightDM)

- Comprehensive deployment guide ([`KC_CONFIG.md`](KC_CONFIG.md))

<br/>
<br/>

## Installation

### Detailed instruction with tabs (RPM, DEB, tar.gz)

Available [here](https://revalew.github.io/pam-keycloak-oidc/install)

<br/>

### RPM (RHEL / Oracle Linux / Rocky / Alma)

**Install latest version:**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -i pam-keycloak-oidc_amd64.rpm
```

**Upgrade (preserves your `.tml` config):**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -U pam-keycloak-oidc_amd64.rpm
```

> [!NOTE]
>
> `arm64` packages are also available - replace `amd64` with `arm64` in the URL above.

<br/>
<br/>

### What the package installs

```bash
rpm -ql pam-keycloak-oidc
```

<div align="center">

| File                                                   | Purpose                                   |
| ------------------------------------------------------ | ----------------------------------------- |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc`             | PAM binary                                |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`         | Config (edit this - preserved on upgrade) |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml.example` | Reference config template                 |
| `/opt/pam-keycloak-oidc/check-keycloak-health.sh`      | Health check script for PAM fast-fail     |
| `/opt/pam-keycloak-oidc/test_token.sh`                 | Test script for quick role validation     |

</div>

After installation, edit the `.tml` config and health check script, then configure PAM and SSHD.
See [`KC_CONFIG.md`](KC_CONFIG.md) for a complete deployment guide with Keycloak, AD and Yubikey.

<br/>
<br/>

## Credits

- Original project by [zhaow-de](https://github.com/zhaow-de/pam-keycloak-oidc)

- Thanks [MattiL](https://github.com/MattiL/pam-keycloak-oidc) for the [alternative signing method](https://github.com/MattiL/pam-keycloak-oidc/commit/e1815d9f0d2db0e38a49feff66cb99992f9af8c3) support and [OTP configurability](https://github.com/MattiL/pam-keycloak-oidc/commit/7ec9520711cb88e175731c40d870bfea7de20a7f) inspiration

- Thanks @willstott101 for adding [arm64 support](https://github.com/willstott101/pam-keycloak-oidc/commit/554076f40a597ab0ec24a1578e624b55d2686111) in the build pipeline
