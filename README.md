# pam-keycloak-oidc

**Current version: 1.1.5**

PAM module connecting to [Keycloak](https://www.keycloak.org/) for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or TOTP (Time-based One-time Password) is supported.

In theory, it should work with any identity provider which supports OpenID Connect 1.0 or OAuth2 with grant type
`password`, although it is only tested with Keycloak 11.x adn 12.x.

## Installation

1.  Create a new Role at Keycloak, e.g. `demo-pam-authentication`. (Assuming the server is at
    `https://keycloak.example.com`)

2.  Create a new Client Scope, e.g. `pam_roles`:
    * Protocol: `openid-connect`
    * Display On Consent Screen: `OFF`
    * Include in Token Scope: `ON`
    * Mapper:
        * Name: e.g. `pam roles`
        * Mapper Type: `User Realm Role`
        * Multivalued: `ON`
        * Token Claim Name: `pam_roles` (the name of the Client Scope)
        * Claim JSON Type: `String`
        * Add to ID token: `OFF`
        * Add to access token: `ON`
        * Add to userinfo: `OFF`
    * Scope:
        * Effective Roles: `demo-pam-authentication` (the name of the Role)

3.  Create a new Keycloak Client:
    * Client ID: `demo-pam` (or whatever valid client name)
    * Enabled: `ON`
    * Consent Required: `OFF`
    * Client Protocol: `openid-connect`
    * Access Type: `confidential`
    * Standard Flow Enabled: `ON`
    * Implicit Flow Enabled: `OFF`
    * Direct Access Grants Enabled: `ON`
    * Service Accounts Enabled: `OFF`
    * Authorization Enabled: `OFF`
    * Valid Redirect URIs: `urn:ietf:wg:oauth:2.0:oob`
    * Fine Grain OpenID Connect Configuration:
        * Access Token Signature Algorithm: e.g. `RS256` (we need to put this in the config file later)
    * Client Scopes:
        * Assigned Default Client Scopes: `pam_roles`
    * Scope:
        * Full Scope Allowed: `OFF`
        * Effective Roles: `demo-pam-authentication`
       
4.  Assign the role `demo-pam-authentication` to relevant users. A common practice is to assign the role to a Group,
    then make the relevant users join that group. Refer to Keycloak documents for the HOWTO.

5.  Download the precompiled binary from Github, e.g. as `/opt/pam-keycloak-oidc/pam-keycloak-oidc`. In case the
system is not amd64, compile this golang application for the appropriate architecture.

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
    ```

8.  Local "test":
    ```shell
    # without MFA. Assuming a user test1 with password password1
    export PAM_USER=test1
    echo password1 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
    # with MFA. Assuming a user test2 with password password2, at the moment the MFA code is 987654
    export PAM_USER=test2
    echo password2987654 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
    ```
    You should see message: "...(test2) Authentication succeeded"

9.  Config PAM. Create PAM config file, e.g. `/etc/pam.d/radiusd`
    ```
    account	required			pam_permit.so
    auth	[success=1 default=ignore]	pam_exec.so	expose_authtok	log=/var/log/pam-keycloak-oidc.log	/opt/pam-keycloak-oidc/pam-keycloak-oidc
    auth	requisite			pam_deny.so
    auth	required			pam_permit.so
    ```
10.  That's it.

## MFA/TOTP handling

At Github, there are already many repos implemented PAM<->OAuth2/OIDC. 

PAM supports only username and password, while it does not provide the third place for the one-time code. However, 
for online authentication and authorization, MFA is fastly becoming the standard which is enforced for many scenarios.
We have to "embed" the OTP code either into the username or the password. This application supports both.

### Simple case

Users could put the 6-digits OTP code right after the real password. For instance, password `SuperSecure` becomes 
`SuperSecure123987` if at the moment the OTP code is `123987`. This is the standard approach, because what's dynamic
remains dynamic.

### "Hardcoded" case

We have a scenario, where all the users are enforced to have MFA because a special RP requires it mandatorily, but
a small group of users (our developers) should be able to access a VPN server authorizing users using the RADIUS
protocol. The setup is like: `SoftEther VPN Server <-> FreeRADIUS <-> PAM <-> Keycloak OIDC`. The OS built-in VPN client
of both macOS and Windows do not prompt the password if the saved credential is wrong. Several additional steps are
required to set the password each time for the VPN connection. To work it around, this "hardcoded" case is introduced
to make both the username and password static even when MFA is enabled.

**IMPORTANT: For environment requires high security standard, this approach should be used, because the MFA token
could be calculated by anyone who knows the username!!**

There are many TOTP tools, e.g. 1Password, LastPass, Authy, etc, could make the MFA config string visible. The MFA
config string looks like:
```
otpauth://totp/demo-pam:test2?secret=NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN&digits=6&algorithm=SHA1&issuer=demo-pam&period=30
```
The `secret` is the seed of how the time-based one-time password is generated. Having the secret will be able to produce
the MFA token assuming the clocks are in sync.

We "encode" the secret directly into the username for the PAM authentication, so that fixed strings can be saved, while
this PAM module calculates the MFA token each time when it is needed using the secret.

This application is not only a PAM module, it calculates the "username" which combines the real username together with
the MFA secret by doing: `encoded-username = A85Encode(XOR(real-username + ":" + totp-secret, xor-key))`. This is the
reason why we have compiled binary for different operating systems to download.

To compute the encoded username:
```shell
pam-keycloak-oidc <real-username> <TOTP secret>
# example command
> pam-keycloak-oidc test2 NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN
# example output
Your secret username: #6l4i6!44m3"$N'6!?JT0I^!d#?MsC3Xu
```

To verify the encoded username:
```shell
pam-keycloak-oidc <encoded-username>
# example command
> pam-keycloak-oidc "#6l4i6\!44m3\"\$N'6\!?JT0I^\!d#?MsC3Xu"
# example output
Your real username: 'test2'. Your TOTP secret: 'NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN'. Your TOTP token for now is: '068724'.
```

Because of the A85 encoding, the encoded username normally requires escaping to put as the argument for a shell command.
An easier approach would be to use a local file for it.
```shell
# put the string #6l4i6!44m3"$N'6!?JT0I^!d#?MsC3Xu in a file. e.g. enc-pwd
> pam-keycloak-oidc $(cat enc-pwd)
```

## Application Logic

It follows the standard PAM application logic: take the username from environment variable `PAM_USER`, take the password
from `stdin` pipe, validate the credential, and return `0` if it is successful, or a non-zero value for failure.

## Why golang?

The logic of this application is simple:
1.  Captures the PAM authentication request. When it arrives, issue a request to OAuth2 IdP with grant_type `password`
2.  Decode and validate the received `access_token` (a JWT token), and check the roles the user has
3.  If the user has the pre-defined role for VPN, accept the PAM request, otherwise, reject it.

In principle any mainstream programming language can do the job, including Python and JavaScript/TypeScript which are
highly popular and adopted. However, PAM authentication module is too close to Linux OS, having an application requires
an interpreter seems not a good fit with this particular deployment scenario.

Ansi C or C++ is the default choice for Linux, but the OAuth2 or OpenID Connect support is probably too low level.
Rust and Go could be the second-tier candidates. Rust is stroke through as the default AWS CodeBuild image does not
have the compiler and package manager built-in. Go was chosen as the programming language for this application.  
