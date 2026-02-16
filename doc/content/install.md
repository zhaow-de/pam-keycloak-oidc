---
weight: 1
title: "Getting started"
---

# Getting started

## Installation

{{< tabs "installation" >}}

{{% tab "RPM" %}}

### RPM (RHEL / Oracle Linux / Rocky / Alma)

**Latest version:**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -i pam-keycloak-oidc_amd64.rpm
```

**Specific version:**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/download/v1.5.2/pam-keycloak-oidc_1.5.2_amd64.rpm

sudo rpm -i pam-keycloak-oidc_1.5.2_amd64.rpm
```

**Upgrade (preserves your `.tml` config):**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -U pam-keycloak-oidc_amd64.rpm
```

> Replace `amd64` with `arm64` for ARM systems.

{{% /tab %}}

{{% tab "DEB" %}}

### DEB (Debian / Ubuntu)

**Latest version:**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.deb

sudo dpkg -i pam-keycloak-oidc_amd64.deb
```

**Specific version:**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/download/v1.5.2/pam-keycloak-oidc_1.5.2_amd64.deb

sudo dpkg -i pam-keycloak-oidc_1.5.2_amd64.deb
```

> Replace `amd64` with `arm64` for ARM systems.

{{% /tab %}}

{{% tab "tar.gz" %}}

### tar.gz (manual)

The tar.gz archive contains the binary, a reference config template, and a health check script.

**Latest version:**

```shell
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_linux_amd64.tar.gz

tar -xf pam-keycloak-oidc_linux_amd64.tar.gz
```

**Install to `/opt`:**

```shell
sudo mkdir -p /opt/pam-keycloak-oidc

sudo mv pam-keycloak-oidc /opt/pam-keycloak-oidc/
sudo mv packaging/pam-keycloak-oidc.tml.example /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
sudo mv packaging/check-keycloak-health.sh /opt/pam-keycloak-oidc/

sudo chmod 755 /opt/pam-keycloak-oidc/pam-keycloak-oidc
sudo chmod 755 /opt/pam-keycloak-oidc/check-keycloak-health.sh
sudo chmod 600 /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
```

> Replace `amd64` with `arm64` for ARM systems.

{{% /tab %}}

{{< /tabs >}}

### What the package installs

| File                                                   | Purpose                                   |
| ------------------------------------------------------ | ----------------------------------------- |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc`             | PAM binary                                |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`         | Config (edit this — preserved on upgrade) |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml.example` | Reference config template                 |
| `/opt/pam-keycloak-oidc/check-keycloak-health.sh`      | Health check script for PAM fast-fail     |

## Configuration

{{% steps %}}

1. Edit the configuration file. See [Configuration](../config) for field reference.
   ```shell
   sudo vim /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
   ```
   Refer to the [specific IdP server](../servers/) guide for Keycloak settings.

2. "Local" validation:
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

3. Configure PAM. Create PAM config file, e.g. `/etc/pam.d/radiusd`
   ```
   account	required			pam_permit.so
   auth	[success=1 default=ignore]	pam_exec.so	expose_authtok	log=/var/log/pam-keycloak-oidc.log	/opt/pam-keycloak-oidc/pam-keycloak-oidc
   auth	requisite			pam_deny.so
   auth	required			pam_permit.so
   ```

{{% /steps %}}

{{% hint warning %}}
**Shell escaping:** If your client secret contains special characters (e.g., `!`, `#`, `$`), be aware
that bash may interpret them. The `!!` sequence triggers bash history expansion, and `$` starts variable
substitution. Always use **single quotes** when setting secrets in shell, or write them directly in the `.tml`
config file where no shell interpretation occurs:

```shell
# WRONG — bash expands !! and $
export SECRET="abc!!def$ghi"
# RIGHT — use single quotes in shell
export SECRET='abc!!def$ghi'
# RIGHT — in the .tml config file, TOML handles double quotes correctly
# client-secret="abc!!def$ghi"
```
{{% /hint %}}
