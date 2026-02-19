# Keycloak 12.x

> **WARNING:** This guide was written for Keycloak 12.x and may not accurately reflect the current Admin Console UI.
> For Keycloak 17 and later (Quarkus distribution), see [Keycloak 26.x](../keycloak-26.x/).
> Key differences: the `/auth/` URL prefix was removed, "Access Type" was replaced with "Client authentication" toggle,
> and the Admin Console was completely redesigned in Keycloak 19.

1.  Create a new Role at Keycloak, e.g. `demo-pam-authentication`. (Assuming the server is at
    `https://keycloak.example.com`)

2.  Create a new Client Scope, e.g. `pam_roles`:
    - Protocol: `openid-connect`
    - Display On Consent Screen: `OFF`
    - Include in Token Scope: `ON`
    - Mapper:
      - Name: e.g. `pam roles`
      - Mapper Type: `User Realm Role`
      - Multivalued: `ON`
      - Token Claim Name: `pam_roles` (the name of the Client Scopebumpsemver)
      - Claim JSON Type: `String`
      - Add to ID token: `OFF`
      - Add to access token: `ON`
      - Add to userinfo: `OFF`
    - Scope:
      - Effective Roles: `demo-pam-authentication` (the name of the Role)

3.  Create a new Keycloak Client:
    - Client ID: `demo-pam` (or whatever valid client name)
    - Enabled: `ON`
    - Consent Required: `OFF`
    - Client Protocol: `openid-connect`
    - Access Type: `confidential`
    - Standard Flow Enabled: `ON`
    - Implicit Flow Enabled: `OFF`
    - Direct Access Grants Enabled: `ON`
    - Service Accounts Enabled: `OFF`
    - Authorization Enabled: `OFF`
    - Valid Redirect URIs: `urn:ietf:wg:oauth:2.0:oob`
    - Fine Grain OpenID Connect Configuration:
      - Access Token Signature Algorithm: e.g. `RS256` (we need to put this in the config file later)
    - Client Scopes:
      - Assigned Default Client Scopes: `pam_roles`
    - Scope:
      - Full Scope Allowed: `OFF`
      - Effective Roles: `demo-pam-authentication`

4.  Assign the role `demo-pam-authentication` to relevant users. A common practice is to assign the role to a Group,
    then make the relevant users join that group. Refer to Keycloak documents for the HOWTO.

5.  Download the precompiled binary from Github, e.g. as `/opt/pam-keycloak-oidc/pam-keycloak-oidc`. In case the
    system is not amd64 or arm64, compile this golang application for the appropriate architecture.

6.  ```shell
    chmod +x /opt/pam-keycloak-oidc/pam-keycloak-oidc
    ```

7.  Create the configuration file at the same directory, with the same filename as the binary plus a `.tml` file
    extension. e.g.:
    ```shell
    vim /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
    ```
    Set parameters at the configuration file:
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
