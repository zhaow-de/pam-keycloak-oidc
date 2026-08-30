---
weight: 20
title: "Configuration file"
---

# Configuration file

Example:

```toml
# name of the dedicated OIDC client at Keycloak
client-id="demo-pam"
# the secret of the dedicated client
client-secret="561319ba-700b-400a-8000-5ab5cd4ef3ab"
# special callback address for no callback scenario
redirect-url="urn:ietf:wg:oauth:2.0:oob"
# OAuth2 scope to be requested, which contains the role information of a user
scope="pam_roles"
# name of the role to be matched, only Keycloak users who is assigned with this role could be accepted
vpn-user-role="demo-pam-authentication"
# retrieve from the meta-data at https://keycloak.example.com/auth/realms/demo-pam/.well-known/openid-configuration
endpoint-auth-url="https://keycloak.example.com/auth/realms/demo-pam/protocol/openid-connect/auth"
endpoint-token-url="https://keycloak.example.com/auth/realms/demo-pam/protocol/openid-connect/token"
# 1:1 copy, to `fmt` substituion is required
username-format="%s"
# to be the same as the particular Keycloak client
access-token-signing-method="RS256"
# a key for XOR masking. treat it as a top secret
xor-key="scmi"
# use only otp code for auth
otp-only=false
```
