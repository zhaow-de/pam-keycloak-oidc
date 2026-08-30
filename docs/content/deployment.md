---
weight: 40
title: "Production deployment"
---

# Production deployment

[Getting started](../install) is enough to prove the module works. This page covers running it as
the SSH authentication path on a Linux server: packages, SELinux, the PAM stack, and how to get out
again if it goes wrong.

The examples use Oracle Linux / RHEL 9 with SELinux enforcing. Debian-family systems need the same
steps minus the SELinux ones.

> [!CAUTION]
> Every change below is applied while you already have a working SSH session. **Keep that session
> open and test from a second terminal.** A broken PAM stack locks out every new login, and the
> session you are holding is the only way back in.

## 1. Install the package

Download the `.rpm` or `.deb` for your architecture from
[the releases page](https://github.com/zhaow-de/pam-keycloak-oidc/releases), then:

```shell
sudo rpm -i pam-keycloak-oidc_*_amd64.rpm      # RHEL family
sudo dpkg -i pam-keycloak-oidc_*_amd64.deb     # Debian family
```

The package installs the binary, a configuration template and the helper scripts under
`/opt/pam-keycloak-oidc/`, and sets the SELinux context the PAM stack needs.

Upgrading keeps your configuration — the `.tml` is marked as a config file, so the package manager
leaves your edited copy in place:

```shell
sudo rpm -U pam-keycloak-oidc_*_amd64.rpm
sudo dpkg -i pam-keycloak-oidc_*_amd64.deb
```

## 2. Write the configuration

```shell
sudo vim /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
sudo chmod 0600 /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
```

The file holds the client secret, so it must not be world-readable. See
[the configuration reference](../config) for every key; the values below are the ones a server
deployment cares about.

```toml
# -- Keycloak connection --
client-id     = "demo-pam"
client-secret = "YOUR_CLIENT_SECRET"
redirect-url  = "urn:ietf:wg:oauth:2.0:oob"

# OAuth2 scope, and the JWT claim the roles are read from. Must equal the
# Token Claim Name of the role mapper.
scope = "pam_roles"

# The role required on THIS group of servers. Usually the only key that differs
# between one server group and another.
vpn-user-role = "demo-pam-authentication"

# -- Endpoints, all from the realm's .well-known/openid-configuration --
endpoint-auth-url  = "https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/auth"
endpoint-token-url = "https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/token"
jwks-url           = "https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/certs"
issuer-url         = "https://keycloak.example.com/realms/demo-pam"

# -- Token validation --
username-format = "%s"
# Only enable after adding the audience mapper; a stock Keycloak token carries
# aud="account" and would be rejected.
verify-audience = false

# XOR key used by the encoded-username mode. Treat it as a secret.
xor-key = "some-secret-string"

# -- OTP --
otp-only = false
```

Running several groups of servers against one realm means one role per group, and only
`vpn-user-role` changes:

| Server group | `vpn-user-role` |
|---|---|
| Development | `dev-ssh` |
| Staging | `staging-ssh` |
| Production | `prod-ssh` |

## 3. Point the health check at your realm

`/opt/pam-keycloak-oidc/check-keycloak-health.sh` decides whether Keycloak is reachable *before*
the user is prompted for a password. Set the two values at the top of it:

```shell
KC_URL="https://keycloak.example.com"
KC_REALM="demo-pam"
```

When the check fails, PAM fails immediately and SSH moves on to the next authentication method —
which is what makes the [YubiKey fallback](../yubikey-fallback) usable during a Keycloak outage.
Without it, every login instead waits for the token request to time out.

## 4. SELinux context

The post-install script sets `bin_t` on everything in `/opt/pam-keycloak-oidc/`. To check, or to
fix a hand-installed copy:

```shell
ls -Z /opt/pam-keycloak-oidc/
# every file should show ...:object_r:bin_t:s0

chcon -t bin_t /opt/pam-keycloak-oidc/pam-keycloak-oidc
chcon -t bin_t /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
chcon -t bin_t /opt/pam-keycloak-oidc/check-keycloak-health.sh
```

> [!CAUTION]
> Never run `restorecon -Rv` on `/opt/pam-keycloak-oidc/`. It resets the context to `usr_t`, which
> `sshd` may not execute, and SSH authentication stops working.

## 5. Trust the Keycloak certificate

The module verifies TLS like any Go program, so a private CA has to be in the system trust store:

```shell
openssl s_client -connect keycloak.example.com:443 \
  -servername keycloak.example.com -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN/,/END/{print}' > /etc/pki/ca-trust/source/anchors/keycloak-chain.crt
update-ca-trust
```

If the hostname does not resolve on the server, add it to `/etc/hosts` before going further —
a DNS failure and a certificate failure look similar in the log.

## 6. Test before touching PAM

```shell
export PAM_USER=testuser
echo 'MyPassword123456' | /opt/pam-keycloak-oidc/pam-keycloak-oidc
#     password immediately followed by the 6-digit OTP, no separator
```

A working attempt logs `...(testuser) Authentication succeeded`.

| Message | Cause | Fix |
|---|---|---|
| `panic: integer divide by zero` | `xor-key` is empty | Set `xor-key` |
| `JWKS unavailable` | Keycloak unreachable from this host | Check DNS, the CA certificate, the firewall |
| `x509: certificate signed by unknown authority` | Private CA not trusted | Section 5 |
| `Access token failed verification: ... iss` | `issuer-url` does not match the token | Copy `issuer` from `.well-known/openid-configuration` |
| `Access token failed verification: ... aud` | `verify-audience` on without an audience mapper | Add the mapper, or set `verify-audience = false` |
| `authorization failed` | Role missing from the claim | Check the role mapper and the user's role |

## 7. Configure sshd

```shell
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

On RHEL 9 and Oracle Linux 9, `/etc/ssh/sshd_config.d/50-redhat.conf` sets
`ChallengeResponseAuthentication no`, and because `Include` sits at the top of `sshd_config` it wins.
Comment it out first, or `keyboard-interactive` never runs:

```shell
sed -i 's/^ChallengeResponseAuthentication no/#ChallengeResponseAuthentication no/' \
  /etc/ssh/sshd_config.d/50-redhat.conf
```

Then in `/etc/ssh/sshd_config`:

```
# Accept EITHER publickey OR keyboard-interactive — the space means OR
AuthenticationMethods publickey keyboard-interactive:pam

PubkeyAuthentication yes
PasswordAuthentication no

KbdInteractiveAuthentication yes          # RHEL/OL 9
ChallengeResponseAuthentication yes       # RHEL/OL 8; harmless alongside the above

UsePAM yes
```

Without the YubiKey fallback, drop the `AuthenticationMethods` line and leave the rest.

## 8. Configure PAM for SSH

```shell
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
```

```
#%PAM-1.0
# Step 1 — is Keycloak reachable? Failure dies here so SSH can try publickey.
auth [success=ok ignore=ignore default=die] pam_exec.so quiet type=auth \
  /opt/pam-keycloak-oidc/check-keycloak-health.sh

# Step 2 — authenticate against Keycloak.
auth [success=done ignore=ignore default=die] pam_exec.so expose_authtok \
  quiet type=auth log=/var/log/pam-keycloak-oidc.log \
  /opt/pam-keycloak-oidc/pam-keycloak-oidc

# Step 3 — satisfy the setcred phase, which neither pam_exec call handles.
auth optional pam_permit.so

account   required    pam_sepermit.so
account   required    pam_nologin.so
account   include     password-auth
password  include     password-auth
session   required    pam_selinux.so close
session   required    pam_loginuid.so
session   required    pam_selinux.so open env_params
session   required    pam_namespace.so
session   optional    pam_keyinit.so force revoke
session   optional    pam_motd.so
session   include     password-auth
session   include     postlogin
```

Three details in that stack are load-bearing, and each one produces a confusing failure if dropped:

- **`type=auth`** makes `pam_exec.so` run the command only during the authenticate phase. During
  `setcred` it returns `PAM_IGNORE` instead of running the binary a second time.
- **`ignore=ignore`** stops that `PAM_IGNORE` from falling through to `default=die`, which would
  deny every login at the `setcred` step.
- **`pam_permit.so`** answers the `setcred` phase. With both `pam_exec` lines ignoring it, no module
  would succeed there, and PAM requires at least one.

> [!CAUTION]
> Do not add `pam_deny.so` to this stack. It fails every PAM function including `setcred`, giving
> `fatal: PAM: pam_setcred(): Permission denied` and killing the session immediately after a
> successful login. `default=die` already covers the authenticate phase.

## 9. Configure PAM for sudo

```shell
cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
```

Add this as the first `auth` line of `/etc/pam.d/sudo`:

```
auth sufficient pam_exec.so expose_authtok quiet log=/var/log/pam-keycloak-oidc.log /opt/pam-keycloak-oidc/pam-keycloak-oidc
```

`sudo` needs no health check: if Keycloak is unavailable the line simply fails and PAM falls through
to the local password.

## 10. Create the log file and restart

```shell
touch /var/log/pam-keycloak-oidc.log
chmod 664 /var/log/pam-keycloak-oidc.log
restorecon -v /var/log/pam-keycloak-oidc.log

systemctl restart sshd
```

Now log in from a **second** terminal. Keep the first one open until it works.

## 11. SELinux network policy

SELinux blocks the outbound HTTPS call the first time, and the denial only appears in the audit log
after an attempt. Make one login attempt, then:

```shell
ausearch -c 'pam-keycloak-' --raw | audit2allow -M pam-keycloak-oidc-allow
semodule -i pam-keycloak-oidc-allow.pp

ausearch -c 'sshd' --raw | audit2allow -M sshd-pam-keycloak
semodule -i sshd-pam-keycloak.pp
```

## 12. Create local accounts

The module authenticates and authorizes; it does not create users. Each Keycloak user still needs a
local account with a matching username:

```shell
useradd -m username
usermod -aG wheel username   # only where sudo is wanted
```

## 13. Onboarding a user

1. **Keycloak** — create the user, set a non-temporary password, add `Configure OTP` to the required
   actions, and put them in the group that carries the server-group role.
2. **Each server** — create the local account as in section 12.
3. **The user** — visits `https://keycloak.example.com/realms/demo-pam/account`, logs in, and is
   shown the OTP enrolment QR code. Any TOTP application will do.
4. **Logging in** — at the password prompt, the password and the current OTP are typed as one
   string with no separator: `MyPassword847291`.

## 14. Rollback

The backups taken in sections 7–9 are the way out:

```shell
cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
systemctl restart sshd
```

## 15. File reference

| File | Purpose | Mode |
|---|---|---|
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc` | The module | 755 |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml` | Configuration, holds the client secret | 600 |
| `/opt/pam-keycloak-oidc/check-keycloak-health.sh` | Reachability check used by the PAM stack | 755 |
| `/etc/pam.d/sshd` | PAM stack for SSH | — |
| `/etc/pam.d/sudo` | PAM stack for sudo | — |
| `/etc/ssh/sshd_config` | `AuthenticationMethods` and friends | — |
| `/var/log/pam-keycloak-oidc.log` | Module log, grep it for `Authentication succeeded` | 664 |

Everything under `/opt/pam-keycloak-oidc/` needs the SELinux context `bin_t`.
