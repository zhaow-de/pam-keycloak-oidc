---
weight: 20
title: 'Configuration file'
---

# Configuration file

The configuration file must be placed in the same directory as the binary, with the same filename plus a `.tml`
extension. For example, if the binary is at `/opt/pam-keycloak-oidc/pam-keycloak-oidc`, the config file must be
`/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`.

Example:

```toml
# name of the dedicated OIDC client at Keycloak
client-id="demo-pam"
# the secret of the dedicated client
client-secret="561319ba-700b-400a-8000-5ab5cd4ef3ab"
# special callback address for no callback scenario
redirect-url="urn:ietf:wg:oauth:2.0:oob"
# OAuth2 scope to be requested, which contains the role information of a user
# this value is also used as the JWT claim key for role lookup
scope="pam_roles"
# name of the role to be matched, only Keycloak users who is assigned with this role could be accepted
vpn-user-role="demo-pam-authentication"
# retrieve from the meta-data at https://keycloak.example.com/realms/demo-pam/.well-known/openid-configuration
endpoint-auth-url="https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/auth"
endpoint-token-url="https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/token"
# JWKS endpoint for JWT signature verification (required)
jwks-url="https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/certs"
# issuer URL for token issuer validation (required, must match "iss" claim in token)
issuer-url="https://keycloak.example.com/realms/demo-pam"
# 1:1 copy, no `fmt` substitution is required
username-format="%s"
# to be the same as the particular Keycloak client
access-token-signing-method="RS256"
# a key for XOR masking. treat it as a top secret
xor-key="scmi"
# use only otp code for auth
otp-only=false
# require OTP suffix in password (reject if missing). Default: false
otp-require=false
# number of OTP characters to extract from password suffix. Default: "6"
otp-length="6"
# regex character class for OTP characters. Default: "\d" (digits only)
# examples: "\d" for numeric, "[a-zA-Z0-9]" for alphanumeric
otp-class="\d"
```

## Field reference

| Field                         | Required | Description                                                                                  |
| ----------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| `client-id`                   | Yes      | OIDC client ID configured in Keycloak                                                        |
| `client-secret`               | Yes      | Client secret from the Credentials tab                                                       |
| `redirect-url`                | Yes      | Use `urn:ietf:wg:oauth:2.0:oob` for non-interactive flows                                    |
| `scope`                       | Yes      | OAuth2 scope containing role claims; also used as the JWT claim key                          |
| `vpn-user-role`               | Yes      | Role name to match in the token claims                                                       |
| `endpoint-auth-url`           | Yes      | OIDC authorization endpoint                                                                  |
| `endpoint-token-url`          | Yes      | OIDC token endpoint                                                                          |
| `jwks-url`                    | Yes      | JWKS endpoint for fetching public keys (must use HTTPS)                                      |
| `issuer-url`                  | Yes      | Expected token issuer (must match the `iss` claim)                                           |
| `username-format`             | Yes      | Format string for the username (`%s` for pass-through)                                       |
| `access-token-signing-method` | No       | Expected JWT signing algorithm (e.g., `RS256`, `ES256`, `EdDSA`)                             |
| `xor-key`                     | No       | XOR key for encoding/decoding the hardcoded username (default: `"scmi"`)                     |
| `otp-only`                    | No       | Set to `true` to accept OTP code without password (default: `false`)                         |
| `otp-require`                 | No       | Set to `true` to reject authentication if no valid OTP suffix is found (default: `false`)    |
| `otp-length`                  | No       | Number of OTP characters to extract from password suffix (default: `6`)                      |
| `otp-class`                   | No       | Regex character class for OTP characters (default: `\d`). Use `[a-zA-Z0-9]` for alphanumeric |
| `extra-parameters`            | No       | Additional key-value pairs to include in the token request                                   |

> **Note:** The `jwks-url` and `issuer-url` fields are required in this fork. They enable cryptographic
> signature verification and issuer validation of the JWT access token. The token audience is validated
> against `client-id`. If you need a custom audience claim, configure an Audience mapper in Keycloak
> (see [Keycloak 26.x guide](servers/keycloak-26.x/)).
