# Keycloak 26.x (Quarkus distribution)

This guide covers setting up Keycloak 26.x for use with pam-keycloak-oidc.
Tested with Keycloak 26.3.2 (Docker).

For a comprehensive end-to-end deployment guide including LDAP/AD federation, PAM configuration,
SELinux, SSHD setup, and YubiKey PIV fallback, see
[KC_CONFIG.md](https://github.com/revalew/pam-keycloak-oidc/blob/main/KC_CONFIG.md).

## 1. Create a Realm Role

**Realm roles** (left menu) **-> Create role:**

- Role name: `demo-pam-authentication`

This role will be assigned to users who are allowed to authenticate through the PAM module.

## 2. Create a Client Scope

**Client scopes** (left menu) **-> Create client scope:**

| Field | Value |
|---|---|
| Name | `pam_roles` |
| Type | Default |
| Protocol | OpenID Connect |

Inside `pam_roles` -> **Mappers** tab -> **Configure a new mapper** -> **User Realm Role:**

| Field | Value |
|---|---|
| Name | `pam roles` |
| Multivalued | On |
| Token Claim Name | `pam_roles` (must match the scope name and the `scope` config field) |
| Claim JSON Type | String |
| Add to ID token | Off |
| Add to access token | On |
| Add to userinfo | Off |

## 3. Create an OIDC Client

**Clients** (left menu) **-> Create client:**

| Setting | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `demo-pam` |

**Next** (Capability config):

| Setting | Value |
|---|---|
| Client authentication | On |
| Authorization | Off |
| Authentication flow | Standard flow: On, Direct access grants: On |

**Next** (Login settings):

| Setting | Value |
|---|---|
| Valid redirect URIs | `urn:ietf:wg:oauth:2.0:oob` |

**Save**, then go to the **Credentials** tab and copy the **Client Secret**.

### 3.1. Assign Client Scope

**Clients -> demo-pam -> Client scopes** tab **-> Add client scope:**

Select `pam_roles` -> **Add** (as Default).

### 3.2. Configure Audience Mapper

Without an audience mapper, the access token contains `"aud": "account"` instead of
`"aud": "demo-pam"`, causing the PAM module to reject it (audience validation failure).

**Clients -> demo-pam -> Client scopes** tab **-> click `demo-pam-dedicated`** ->
**Add mapper -> By configuration -> Audience:**

| Field | Value |
|---|---|
| Name | `demo-pam-audience` |
| Included Client Audience | `demo-pam` |
| Add to ID token | Off |
| Add to access token | On |

### 3.3. Restrict Scope

**Clients -> demo-pam -> Client scopes** tab **-> Scope** tab:

- Full Scope Allowed: **Off**

Then add only the required role: **Assign role** -> select `demo-pam-authentication`.

### 3.4. Token Signing Algorithm (optional)

**Clients -> demo-pam -> Advanced** tab **-> Fine Grain OpenID Connect Configuration:**

- Access Token Signature Algorithm: `RS256` (default)

Set `access-token-signing-method` in the PAM config to match.

## 4. Assign Roles to Users

A common practice is to assign the role to a Group, then add users to the group.

**Groups** (left menu) **-> Create group** (e.g., `pam-users`) **-> Role mapping** tab **->
Assign role -> select `demo-pam-authentication`.**

Then add users to the group: **Users -> select user -> Groups** tab **-> Join group -> select `pam-users`.**

## 5. Discover Endpoints

All endpoint URLs can be found at the OpenID Connect discovery document:

```
https://keycloak.example.com/realms/YOUR_REALM/.well-known/openid-configuration
```

From this document, extract:
- `authorization_endpoint` -> `endpoint-auth-url`
- `token_endpoint` -> `endpoint-token-url`
- `jwks_uri` -> `jwks-url`
- `issuer` -> `issuer-url`

## 6. Configuration File

Create `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`:

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
# regex character class for OTP characters. Default: '\d' (digits only)
# examples: '\d' for numeric, '[a-zA-Z0-9]' for alphanumeric
otp-class='\d'
```

> **Note:** In Keycloak 17+ (Quarkus distribution), the `/auth/` prefix is no longer part of the
> default URL path. If you migrated from WildFly and still have `/auth/` in your URLs, both forms
> should work (Keycloak redirects the legacy path), but the canonical form without `/auth/` is
> recommended.

## 7. Verify Token Content

To verify the token contains the expected claims, you can use the Keycloak token endpoint directly:

```bash
TOKEN=$(curl -s -X POST \
  "https://keycloak.example.com/realms/YOUR_REALM/protocol/openid-connect/token" \
  -d "client_id=demo-pam" \
  -d "client_secret=YOUR_SECRET" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=testpass123456" \
  -d "scope=pam_roles" | jq -r '.access_token')

# Decode and inspect the token payload (base64)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Expected claims to verify:
- `"iss"` matches `issuer-url`
- `"aud"` contains `demo-pam` (the client ID)
- `"pam_roles"` contains `demo-pam-authentication`
- `"exp"` is present (expiration timestamp)
