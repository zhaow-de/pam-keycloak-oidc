# pam-aad-oidc

A pluggable authentication module (PAM) for authenticating users from Azure Active Directory using OpenID Connect.
This code is derived from [`pam-keycloak-oidc`](https://github.com/zhaow-de/pam-keycloak-oidc).

## Configure Azure Active Directory

1. Create a new `App Registration` in your Azure Active Directory.

   - Set the name to whatever you choose (in this example we will use `pam-aad-oidc`)
   - Set access to `Accounts in this organizational directory only`.
   - Set `Redirect URI` to `Public client/native (mobile & desktop)` with a value of `urn:ietf:wg:oauth:2.0:oob`

2. Under `Certificates & secrets` add a `New client secret`

   - Set the description to `Secret for PAM authentication`
   - Set the expiry time to whatever is relevant for your use-case
   - You must **record the value** of this secret at creation time, as it will not be visible later.

3. Under `API permissions`:
   - Ensure that `Microsoft Graph > User.Read` is enabled
   - Select this and click the `Grant admin consent` button (otherwise manual consent is needed from each user)

## Configure local client

1. Download the latest precompiled binary from `https://github.com/alan-turing-institute/pam-aad-oidc/releases`

2. Install the binary in `/lib/security`

3. Create the `TOML` configuration file in the same directory, with the same filename as the binary plus a `.tml` file
   It should have the following structure:

   ```toml
   # Tenant ID for this AzureAD
   tenant-id="07e4545b-d4e1-e60f-63ab-32a64c0e9346"

   # The Application (client) ID for your registered app
   client-id="0831d551-06ed-db79-d1f3-20a45f0279ae"

   # The (time-limited) client secret generated for this application above
   client-secret="jbi58~72en43pqpdvwg6enb8r0ml3-hq-0ip2s9c"

   # Microsoft.Graph scope to be requested. Unless there is a particular reason not to, use 'user.read'.
   scope="user.read"

   # Name of AAD group that authenticated users must belong to
   group-name="Allowed PAM users"

   # Default domain for AAD users. This will be appended to any users not in `username@domain` format.
   domain="mydomain.onmicrosoft.com"

   # Key used for XOR masking  key for XOR masking. treat it as a top secret
   xor-key="evvwfd6d1e4q8gj"
   ```

4. Local "test":

   ```shell
   # without MFA. Assuming a user test1 with password password1
   export PAM_USER=test1
   echo password1 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
   # with MFA. Assuming a user test2 with password password2, at the moment the MFA code is 987654
   export PAM_USER=test2
   echo password2987654 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
   ```

   You should see message: "...(test2) Authentication succeeded"

5. Config PAM. Create PAM config file, e.g. `/etc/pam.d/radiusd`
   ```
   account	required			pam_permit.so
   auth	[success=1 default=ignore]	pam_exec.so	expose_authtok	log=/var/log/pam-keycloak-oidc.log	/opt/pam-keycloak-oidc/pam-keycloak-oidc
   auth	requisite			pam_deny.so
   auth	required			pam_permit.so
   ```
## MFA/TOTP handling

At Github, there are already many repos implemented PAM<->OAuth2/OIDC.

PAM supports only username and password, while it does not provide the third place for the one-time code.
However, for online authentication and authorization, MFA is fastly becoming the standard which is enforced for many scenarios.
We have to "embed" the OTP code either into the username or the password.
This application supports both.

### Simple case

Users could put the 6-digits OTP code right after the real password.
For instance, password `SuperSecure` becomes `SuperSecure123987` if at the moment the OTP code is `123987`.
This is the standard approach, because what's dynamic remains dynamic.

### "Hardcoded" case

We have a scenario, where all the users are enforced to have MFA because a special RP requires it mandatorily, but a small group of users (our developers) should be able to access a VPN server authorizing users using the RADIUS protocol.
The setup is like: `SoftEther VPN Server <-> FreeRADIUS <-> PAM <-> Keycloak OIDC`.
The OS built-in VPN client of both macOS and Windows do not prompt the password if the saved credential is wrong.
Several additional steps are required to set the password each time for the VPN connection.
To work it around, this "hardcoded" case is introduced to make both the username and password static even when MFA is enabled.

**IMPORTANT: For environment requires high security standard, this approach should be used, because the MFA token could be calculated by anyone who knows the username!!**

There are many TOTP tools, e.g. 1Password, LastPass, Authy, etc, could make the MFA config string visible.
The MFA config string looks like:

```
otpauth://totp/demo-pam:test2?secret=NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN&digits=6&algorithm=SHA1&issuer=demo-pam&period=30
```

The `secret` is the seed of how the time-based one-time password is generated.
Having the secret will be able to produce the MFA token assuming the clocks are in sync.

We "encode" the secret directly into the username for the PAM authentication, so that fixed strings can be saved, while this PAM module calculates the MFA token each time when it is needed using the secret.

This application is not only a PAM module, it calculates the "username" which combines the real username together with the MFA secret by doing: `encoded-username = A85Encode(XOR(real-username + ":" + totp-secret, xor-key))`.
This is the reason why we have compiled binary for different operating systems to download.

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

It follows the standard PAM application logic: take the username from environment variable `PAM_USER`, take the password from `stdin` pipe, validate the credential, and return `0` if it is successful, or a non-zero value for failure.

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
