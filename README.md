# pam-keycloak-oidc

Current version: **2.0.0-a0**

A PAM module connecting to [Keycloak](https://www.keycloak.org/) for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or precisely, TOTP (Time-based One-time Password), is supported.

Visit https://zhaow-de.github.io/pam-keycloak-oidc/ for detailed documentation.

## Credits

* Thanks [@MattiL](https://github.com/mattilinnanvuori) for the [alternative signing method](https://github.com/MattiL/pam-keycloak-oidc/tree/ecc) support
* Thanks [@willstott101](https://github.com/willstott101) for adding [arm64 support](https://github.com/willstott101/pam-keycloak-oidc/commit/554076f40a597ab0ec24a1578e624b55d2686111) in the build pipeline
* Thanks [@ihard](https://github.com/ihard) for the `otp-only` option
* Thanks [@revalew](https://github.com/revalew) for [JWKS signature verification, multi-role authorization and the RPM/DEB packaging](https://github.com/zhaow-de/pam-keycloak-oidc/pull/34)
