---
weight: 1
title: "Getting started"
---

# Getting started

{{% steps %}}

1. Download the precompiled binary file for the corresponding operating system from [Github](https://github.com/zhaow-de/pam-keycloak-oidc/releases), save it to the Linux server, e.g., as `/opt/pam-keycloak-oidc/pam-keycloak-oidc`. In case the
platform is not amd64 or arm64, compile this golang application for the appropriate architecture.

2. ```shell
   chmod +x /opt/pam-keycloak-oidc/pam-keycloak-oidc
   ```

3. Create the configuration file at the same directory, with the same filename as the binary plus a `.tml` file
   extension. e.g.:
   ```shell
   vim /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
   ```

4. Set parameters at the configuration file, refering to the config for [specific IdP server](../servers/) and [described details](../config).

5. "Local" validation:
   ```shell
   # without MFA. Assuming a user test1 with password password1
   export PAM_USER=test1
   echo password1 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
   # with MFA. Assuming a user test2 with password password2, at the moment the MFA code is 987654
   export PAM_USER=test2
   echo password2987654 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
   # with OTP code only (otp-only=true), OTP code is 987654
   # need create Flow without password and set to client, example MFA OpenVPN certificate + OTP
   export PAM_USER=test3
   echo 987654 | /opt/pam-keycloak-oidc/pam-keycloak-oidc
   ```
   You should see message like: "...(test1) Authentication succeeded"

6. Config PAM. Create PAM config file, e.g. `/etc/pam.d/radiusd`
   ```
   account	required			pam_permit.so
   auth	[success=1 default=ignore]	pam_exec.so	expose_authtok	log=/var/log/pam-keycloak-oidc.log	/opt/pam-keycloak-oidcpam-keycloak-oidc
   auth	requisite			pam_deny.so
   auth	required			pam_permit.so
   ```

{{% /steps %}}
