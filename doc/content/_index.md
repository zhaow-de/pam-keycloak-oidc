---
title: "User documentation"
---

_(User documentation for GitHub repo https://github.com/zhaow-de/pam-keycloak-oidc)_

# pam-keycloak-oidc

Current version: **1.4.0**

## Overview

A PAM module connecting to identity providers for user authentication using OpenID Connect protocol,
MFA (Multi-Factor Authentication) or TOTP (Time-based One-time Password) is supported.

In theory, it should work with any identity provider which supports OpenID Connect 1.0 or OAuth2 with grant type
`password`, although it is only tested with [Keycloak](https://www.keycloak.org/).
Please help create PR for the documentation of other established public identity providers.


## MFA/TOTP handling

At Github, there are already many repos implemented PAM<->OAuth2/OIDC.

PAM supports only username and password, while it does not provide the third place for the one-time code. However,
for online authentication and authorization, MFA is fastly becoming the standard which is enforced for many scenarios.
We have to "embed" the OTP code either into the username or the password. This application supports both.

### Simple case

Users could put the 6-digit OTP code right after the real password. For instance, password `SuperSecure` becomes 
`SuperSecure123987` if at the moment the OTP code is `123987`. This is the standard approach, because what's dynamic
remains dynamic.

### "Hardcoded" case

We have a scenario, where all the users are enforced to have MFA because a special RP requires it mandatorily, but
a small group of users (our developers) should be able to access a VPN server authorizing users using the RADIUS
protocol. The setup is like: `SoftEther VPN Server <-> FreeRADIUS <-> PAM <-> Keycloak OIDC`. The OS built-in VPN client
of both macOS and Windows do not prompt the password if the saved credential is wrong. Several additional steps are
required to set the password each time for the VPN connection. To work it around, this "hardcoded" case is introduced
to make both the username and password static even when MFA is enabled.

> [!CAUTION]
> For environment requires high security standard, this approach must _**NOT**_ be used, because the MFA token
could be calculated by anyone who knows the username!!

There are many TOTP tools, e.g. 1Password, LastPass, Authy, etc, could make the MFA config string visible. The MFA
config string looks like:
```
otpauth://totp/demo-pam:test2?secret=NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN&digits=6&algorithm=SHA1&issuer=demo-pam&period=30
```
The "`secret`" (`NQZEW2D2NAZDSUTKINFDQVTUGRZTSSLN` in the example above) is the seed of how the time-based one-time password is generated. Having the secret will be able to produce
the MFA token assuming the clocks are in sync.

We "encode" the secret directly into the username for the PAM authentication, so that fixed strings can be saved, while
this PAM module calculates the MFA token each time when it is needed using the secret.

This application is not only a PAM module, it works also as a command line utility to calculate the "username" which combines the real username together with the MFA secret by doing: `encoded-username = A85Encode(XOR(real-username + ":" + totp-secret, xor-key))`.
This is why we have the application precompiled also for Windows and macOS although PAM authentication approach is not applicable on these platforms.

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
An easier and less error-prone approach would be to use a local file for it.
```shell
# put the string #6l4i6!44m3"$N'6!?JT0I^!d#?MsC3Xu in a file. e.g. enc-pwd
> pam-keycloak-oidc $(cat enc-pwd)
```

## Application Logic

It follows the standard PAM application logic: take the username from environment variable `PAM_USER`, take the password
from `stdin` pipe, validate the credential, and return `0` if it is successful, or a non-zero value for failure.

## Why golang?

The logic of this application is simple:
1.  Capture the PAM authentication request. When it arrives, issue a request to OAuth2 IdP with grant_type `password`
2.  Decode and validate the received `access_token` (a JWT token), and check the roles the user has
3.  If the user has the pre-defined role for VPN, accept the PAM request, otherwise, reject it.

In principle, any mainstream programming language can do the job, including Python and JavaScript/TypeScript which are
highly popular and adopted. However, PAM authentication module is too close to Linux OS, having an application requires
an interpreter seems not a good fit with this particular deployment scenario.

Ansi C or C++ is the default choice for Linux, but the OAuth2 or OpenID Connect support is probably too low level.
Rust and Go could be the second-tier candidates. Rust is stroke through as the default AWS CodeBuild image does not
have the compiler and package manager built-in. Go was chosen as the programming language for this application.
