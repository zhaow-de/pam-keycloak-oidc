# pam-keycloak-oidc

Current version: **1.5.0**

A PAM module connecting to [Keycloak](https://www.keycloak.org/) for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or precisely, TOTP (Time-based One-time Password), is supported.

This is a fork of [zhaow-de/pam-keycloak-oidc](https://github.com/zhaow-de/pam-keycloak-oidc) with the following additions:

* JWKS-based JWT signature verification (using [keyfunc/v3](https://github.com/MicahParks/keyfunc))
* Token issuer and audience validation
* Token expiration enforcement
* `--version` and `--help` CLI flags
* Updated documentation for Keycloak 26.x
* Comprehensive deployment guide ([KC_CONFIG.md](KC_CONFIG.md))

Visit https://revalew.github.io/pam-keycloak-oidc/ for detailed documentation.

## Credits

* Original project by [zhaow-de](https://github.com/zhaow-de/pam-keycloak-oidc)
* Thanks @MattiL for the [alternative signing method](https://github.com/MattiL/pam-keycloak-oidc/tree/ecc) support
* Thanks @willstott101 for adding [arm64 support](https://github.com/willstott101/pam-keycloak-oidc/commit/554076f40a597ab0ec24a1578e624b55d2686111) in the build pipeline
