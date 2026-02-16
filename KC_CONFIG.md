# Keycloak SSH Authentication with 2FA and YubiKey Fallback

## Goal

Set up a complete SSH authentication chain:

1. **LDAP/AD Federation** - Keycloak syncs users from OpenLDAP or Active Directory
2. **SSH via Keycloak + TOTP** - Users authenticate with password + OTP code through a PAM module
3. **Role-based access** - Different server groups require different Keycloak roles
4. **YubiKey PIV fallback** - When Keycloak is down, admins use hardware keys via PKCS#11

Authentication flow: `keyboard-interactive (Keycloak+OTP)` OR `publickey (YubiKey PIV)`.
A health check script detects Keycloak availability and triggers automatic fallback.

---

## 1. Keycloak - Client and Authentication Flow

### 1.1. Create OIDC Client

**Clients -> Create Client:**

| Setting | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `ssh-client` |
| Client authentication | On |
| Authorization | Off |
| Authentication flow | Standard flow + Direct access grants |
| Valid redirect URIs | `urn:ietf:wg:oauth:2.0:oob` |

Save, then go to **Credentials** tab and copy the **Client Secret**.

### 1.2. Create Client Role

**Clients -> ssh-client -> Roles -> Create role:**

- Role name: `linux-ssh`

### 1.3. Create Authentication Flow

**Authentication -> Flows -> find `direct grant` -> ⋮ -> Duplicate -> name: `direct grant role`**

The duplicated flow already contains: Username Validation, Password, Conditional OTP. Keep them.

**Add role check:**

1. Click **Add sub-flow** -> Name: `Access_by_role`, Requirement: **Conditional**
2. Inside sub-flow: **Add execution** -> `Condition - user role` -> set to **Required**
3. Configure (gear icon):
   - Alias: `user_role`
   - User role: `ssh-client linux-ssh`
   - **Negate output: On**
4. Inside sub-flow: **Add execution** -> `Deny access` -> set to **Required**

Logic: if user does NOT have `linux-ssh` (negate=on), condition is met -> deny. Users with the role pass through.

**Final flow structure:**

```
Username Validation                     - Required
Password                                - Required
Direct Grant - Conditional OTP          - Conditional
  ├─ Condition - user configured        - Required
  └─ OTP                                - Required
Access_by_role                          - Conditional
  ├─ Condition - user role (Negate=On)  - Required
  └─ Deny access                        - Required
```

### 1.4. Assign Flow to Client

**Clients -> ssh-client -> Advanced -> Authentication flow overrides:**

- Direct Grant Flow: `direct grant role`
- Browser Flow: leave empty

### 1.5. Configure OTP Policy

**Authentication -> Required actions:**
- Configure OTP: Enabled = **On**, Set as default action = **On**

**Authentication -> Policies -> OTP Policy:**
- Look around window: `2`

### 1.6. Create Client Scope with Role Mapper

This is required for the advanced PAM module (`pam-keycloak-oidc`) which reads roles from a flat JWT claim.

**Client scopes -> Create client scope:**

| Field | Value |
|---|---|
| Name | `ssh_roles` |
| Type | Default |
| Protocol | OpenID Connect |

Inside `ssh_roles` -> **Mappers -> Configure a new mapper -> User Realm Role:**

| Field | Value |
|---|---|
| Name | `realm-roles` |
| Multivalued | On |
| Token Claim Name | `ssh_roles` <- must match scope name exactly |
| Claim JSON Type | String |
| Add to ID token | Off |
| Add to access token | On |
| Add to userinfo | Off |

**Clients -> ssh-client -> Client scopes -> Add client scope -> select `ssh_roles` -> Add (Default)**

### 1.7. Add Audience Mapper

Without this, token has `"aud": "account"` and gets rejected by the PAM module.

**Clients -> ssh-client -> Client scopes -> click `ssh-client-dedicated` -> Add mapper -> By configuration -> Audience:**

| Field | Value |
|---|---|
| Name | `ssh-client-audience` |
| Included Client Audience | `ssh-client` |
| Add to ID token | Off |
| Add to access token | On |

### 1.8. Create Realm Roles (per server group)

Each role is a composite that includes `linux-ssh` (so the auth flow still works).

**Realm roles -> Create role:**

1. Role name: e.g. `dev-ssh` -> Save
2. Inside the role: **Action -> Add associated roles -> Filter by clients -> select `ssh-client linux-ssh` -> Assign**

Repeat for each server group: `qa-ssh`, `staging-ssh`, `prod-ssh`, etc.

### 1.9. Create Groups (optional, simplifies management)

**Groups -> Create group** (e.g. `ssh-dev`)

Open group -> **Role mapping -> Assign role -> select `dev-ssh` -> Assign**

Users added to the group automatically inherit the role.

### 1.10. Create Users

**Users -> Add user:**

1. Fill in: Username, Email, First name, Last name
2. Email verified: **On**
3. Required user actions: add **Configure OTP**
4. **Create** -> Credentials tab -> Set password (Temporary: Off)
5. Groups tab -> Join Group -> select appropriate group

---

## 2. Keycloak - LDAP / Active Directory Federation

### 2.1. OpenLDAP Federation

**User Federation -> Add new provider -> LDAP:**

| Field | Value |
|---|---|
| UI display name | `openldap` |
| Vendor | Other |
| Connection URL | `ldap://openldap-host:389` |
| Enable StartTLS | Off |
| Use Truststore SPI | Always |
| Connection pooling | Off |
| Bind type | simple |
| Bind DN | `cn=admin,dc=example,dc=local` |
| Bind credentials | *(admin password)* |
| Edit mode | READ_ONLY |
| Users DN | `ou=users,dc=example,dc=local` |
| Username LDAP attribute | `mail` |
| RDN LDAP attribute | `mail` |
| UUID LDAP attribute | `entryUUID` |
| User object classes | `inetOrgPerson, organizationalPerson, person` |
| User LDAP filter | `(mail=*)` |
| Search scope | Subtree |
| Import users | On |
| Sync Registrations | On |

Save -> **Action -> Sync all users**.

### 2.2. Active Directory Federation

**Prerequisites:**
- Dedicated service account (e.g. `svc-keycloak-ldap`) - Domain Users only, no elevated permissions
- Firewall open TCP 636 from Keycloak servers to domain controllers
- Root CA certificate exported as PEM

**Import Root CA into Keycloak truststore** (Docker setup - mount as volume, import at container start):

```bash
# Export CA cert from AD
openssl s_client -connect dc01.example.local:636 \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > ad-ca-cert.pem
```

Always import the Root CA, not the leaf certificate of the domain controller.

**User Federation -> Add new provider -> LDAP:**

| Field | Value |
|---|---|
| Vendor | Active Directory |
| Connection URL | `ldaps://DC01.example.local:636` |
| Enable StartTLS | Off |
| Bind DN | `svc-keycloak@example.local` (UPN format) |
| Bind credentials | *(service account password)* |
| Edit mode | READ_ONLY |
| Users DN | `OU=Users,DC=example,DC=local` |
| Username LDAP attribute | `sAMAccountName` <- change from auto-filled `cn` |
| RDN LDAP attribute | `cn` |
| UUID LDAP attribute | `objectGUID` (auto) |
| User object classes | `person, organizationalPerson, user` |
| Search scope | Subtree |
| Pagination | On |
| Import users | On |

**Recommended user filter** (excludes computer accounts, disabled accounts, system accounts):

```
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

> [!NOTE]
> The filter above is shown on a single line. If you format it across multiple lines for readability, make sure to remove all line breaks and extra whitespace before pasting into Keycloak's Custom User LDAP Filter field.

### 2.3. Map AD Groups to Keycloak Roles

**User Federation -> AD provider -> Mappers -> Add mapper:**

| Field | Value |
|---|---|
| Mapper type | `group-ldap-mapper` |
| LDAP Groups DN | `OU=Groups,DC=example,DC=local` |
| Group Name LDAP Attribute | `cn` |
| Group Object Classes | `group` |
| Membership LDAP Attribute | `member` |
| Membership Attribute Type | DN |
| User Groups Retrieve Strategy | `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` |
| Mode | READ_ONLY |

After sync: **Groups -> find imported AD group -> Role mapping -> Assign role -> filter by clients -> select `ssh-client linux-ssh` -> Assign**.

For nested groups use `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY`.

### 2.4. Sync and Verify

1. **Test connection** -> success
2. **Test authentication** (with service account) -> success
3. Save
4. **Action -> Sync all users**
5. **Users -> type `*` in search** -> verify users appear

---

## 3. Linux Server - PAM Module (pam-keycloak-oidc)

This is a modified fork with JWKS signature verification, issuer validation, and audience validation. The upstream version does NOT verify JWT signatures.

### 3.1. Install Package

Install the RPM package from [GitHub Releases](https://github.com/revalew/pam-keycloak-oidc/releases):

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -i pam-keycloak-oidc_amd64.rpm
```

> Replace `amd64` with `arm64` for ARM systems. DEB and tar.gz packages are also available - see [installation docs](https://revalew.github.io/pam-keycloak-oidc/install).

The package installs the binary, config template, health check script, and test script to `/opt/pam-keycloak-oidc/`. SELinux context (`bin_t`) is configured automatically by the post-install script.

**Upgrade (preserves your `.tml` config):**

```bash
wget https://github.com/revalew/pam-keycloak-oidc/releases/latest/download/pam-keycloak-oidc_amd64.rpm

sudo rpm -U pam-keycloak-oidc_amd64.rpm
```

### 3.2. Configuration File

The RPM package installs a config template at `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml`. Edit it:

```bash
sudo vim /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
```

Example configuration (see [config reference](https://revalew.github.io/pam-keycloak-oidc/config) for all fields):

```toml
# -- Keycloak connection --
client-id        = "ssh-client"
client-secret    = "YOUR_CLIENT_SECRET"
redirect-url     = "urn:ietf:wg:oauth:2.0:oob"

# OAuth2 scope - also used as the JWT claim key
# Code does: claims[config.Scope] - must match Token Claim Name in mapper
scope = "ssh_roles"

# -- Required role for THIS server group --
# ONLY setting that differs between server groups
vpn-user-role    = "dev-ssh"

# -- Endpoints --
endpoint-auth-url  = "https://keycloak.example.local/realms/REALM/protocol/openid-connect/auth"
endpoint-token-url = "https://keycloak.example.local/realms/REALM/protocol/openid-connect/token"

# JWKS endpoint for JWT signature verification (required)
jwks-url = "https://keycloak.example.local/realms/REALM/protocol/openid-connect/certs"

# Issuer URL - must match "iss" claim in token (required)
issuer-url = "https://keycloak.example.local/realms/REALM"

# -- Token validation --
username-format              = "%s"
access-token-signing-method  = "RS256"

# XOR key for encoding/decoding hardcoded username (default: "scmi")
xor-key = "some-secret-string"

# -- OTP settings --
# Use only OTP code for auth (no password)
otp-only = false
# Require OTP suffix in password (reject if missing). Default: false
otp-require = false
# Number of OTP characters to extract from password suffix. Default: "6"
otp-length = "6"
# Regex character class for OTP characters. Default: "\d" (digits only)
# Use "[a-zA-Z0-9]" for alphanumeric tokens
otp-class = "\d"
```

```bash
chmod 0600 /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
```

The **only difference** between server groups is `vpn-user-role`:

| Server group | vpn-user-role |
|---|---|
| Development | `dev-ssh` |
| QA | `qa-ssh` |
| Staging | `staging-ssh` |
| Admin | `admin-ssh` |

### 3.3. Health Check Script

The RPM package installs `check-keycloak-health.sh` in `/opt/pam-keycloak-oidc/`. Edit the Keycloak URL and realm:

```bash
sudo vim /opt/pam-keycloak-oidc/check-keycloak-health.sh
```

Set the correct values at the top of the script:

```bash
KC_URL="https://keycloak.example.local"
KC_REALM="REALM"
```

The script checks Keycloak reachability before the password prompt. If Keycloak is down, PAM fails immediately and SSH falls through to publickey (YubiKey PIV).

### 3.4. SELinux Context

The RPM post-install script automatically sets `bin_t` context on all files in `/opt/pam-keycloak-oidc/`. If you need to verify or fix manually:

```bash
# Verify
ls -Z /opt/pam-keycloak-oidc/
# Expected: unconfined_u:object_r:bin_t:s0 on all files

# Fix if needed
chcon -t bin_t /opt/pam-keycloak-oidc/pam-keycloak-oidc
chcon -t bin_t /opt/pam-keycloak-oidc/pam-keycloak-oidc.tml
chcon -t bin_t /opt/pam-keycloak-oidc/check-keycloak-health.sh
# chcon -t bin_t /opt/pam-keycloak-oidc/test_token.sh
```

> **WARNING:** NEVER run `restorecon -Rv` on `/opt/pam-keycloak-oidc/` - it resets context to `usr_t` and breaks PAM.

### 3.5. Import Keycloak CA Certificate

```bash
openssl s_client -connect keycloak.example.local:443 \
  -servername keycloak.example.local -showcerts \
  </dev/null 2>/dev/null | \
  awk '/BEGIN/,/END/{print}' > /etc/pki/ca-trust/source/anchors/keycloak-chain.crt
update-ca-trust
```

### 3.6. DNS Resolution

If DNS does not resolve the Keycloak hostname:

```bash
echo '10.0.0.100 keycloak.example.local' >> /etc/hosts
```

### 3.7. Manual Test (before changing PAM)

**Quick validation with test script** (fetches token, decodes JWT, simulates PAM login):

```bash
sudo /opt/pam-keycloak-oidc/test_token.sh
```

**Manual test:**

```bash
export PAM_USER=testuser
echo 'MyPassword123456' | /opt/pam-keycloak-oidc/pam-keycloak-oidc
#     ^^^ password + 6-digit OTP concatenated, NO separator
# Expected: "Authentication succeeded"
```

**Common errors:**

| Message | Cause | Fix |
|---|---|---|
| `panic: integer divide by zero` | Missing `xor-key` in .tml | Add `xor-key` |
| `Failed to fetch JWKS` | No connection to Keycloak | Check DNS, CA cert, firewall |
| `JWT verification failed: [...] iss` | Issuer mismatch | Check `issuer-url` in .tml |
| `JWT verification failed: [...] aud` | Missing audience mapper | Add Audience mapper (section 1.7) |
| `authorization failed` | Role not in claim | Check mapper (`ssh_roles`) and user role |
| `x509: certificate signed by unknown authority` | Missing CA cert | See section 3.5 |

### 3.8. Configure SSHD

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

**Step 1 - Handle 50-redhat.conf (OL9/RHEL9 only):**

OL9 ships `/etc/ssh/sshd_config.d/50-redhat.conf` with `ChallengeResponseAuthentication no`. Since `Include` is at the top of `sshd_config`, this file is parsed FIRST and blocks `keyboard-interactive`.

```bash
sed -i 's/^ChallengeResponseAuthentication no/#ChallengeResponseAuthentication no/' \
  /etc/ssh/sshd_config.d/50-redhat.conf
```

**Step 2 - Set directives in `/etc/ssh/sshd_config`:**

```
# === SSH Authentication: Keycloak (primary) + YubiKey PIV (fallback) ===
# Accept EITHER publickey OR keyboard-interactive (space = OR)
AuthenticationMethods publickey keyboard-interactive:pam

PubkeyAuthentication yes
PasswordAuthentication no

# OL 9.x (new directive name):
KbdInteractiveAuthentication yes
# OL 8.x (legacy name, both can coexist safely):
ChallengeResponseAuthentication yes

UsePAM yes
```

> If you don't plan to use YubiKey fallback, you can omit `AuthenticationMethods` and use default SSHD config.

### 3.9. Configure PAM (/etc/pam.d/sshd)

```bash
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
```

```bash
cat > /etc/pam.d/sshd << 'EOF'
#%PAM-1.0
# === SSH AUTH: Keycloak with fast-fail health check ===

# Step 1: Check Keycloak reachability
# success -> continue to Keycloak auth
# failure -> die immediately, PAM fails, SSH tries publickey
auth [success=ok ignore=ignore default=die] pam_exec.so quiet type=auth \
  /opt/pam-keycloak-oidc/check-keycloak-health.sh

# Step 2: Authenticate against Keycloak
# success -> grant access (done)
# failure -> deny (wrong password/OTP, die)
auth [success=done ignore=ignore default=die] pam_exec.so expose_authtok \
  quiet type=auth log=/var/log/pam-keycloak-oidc.log \
  /opt/pam-keycloak-oidc/pam-keycloak-oidc

# Step 3: pam_setcred() handler
# pam_exec with type=auth returns PAM_IGNORE for setcred phase,
# pam_permit returns PAM_SUCCESS -> setcred completes correctly
auth optional pam_permit.so

# Standard account/session entries
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
EOF
```

> **CRITICAL:** Do NOT use `pam_deny.so` in this config. It returns error for ALL PAM functions including `setcred`, causing `"fatal: PAM: pam_setcred(): Permission denied"` and immediate session termination. The `default=die` flag on the health check serves the same purpose but only during the `authenticate` phase.

**Why `type=auth`?** - Makes `pam_exec.so` run the command ONLY during `authenticate` phase. During `setcred` it returns `PAM_IGNORE`.

**Why `ignore=ignore`?** - Without it, `PAM_IGNORE` returned during `setcred` is handled by `default=die`, causing immediate denial.

**Why `pam_permit.so`?** - When both `pam_exec` modules return `PAM_IGNORE` during `setcred`, no module handles that phase. PAM requires at least one success - `pam_permit.so` provides it.

### 3.10. Configure PAM for sudo

```bash
cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
```

Add to the beginning of `/etc/pam.d/sudo` (before other `auth` lines):

```
auth sufficient pam_exec.so expose_authtok quiet log=/var/log/pam-keycloak-oidc.log /opt/pam-keycloak-oidc/pam-keycloak-oidc
```

`sudo` doesn't need the health check - if Keycloak is unavailable, it falls back to local password.

### 3.11. Create Log File and Restart

```bash
touch /var/log/pam-keycloak-oidc.log
chmod 664 /var/log/pam-keycloak-oidc.log
restorecon -v /var/log/pam-keycloak-oidc.log

systemctl restart sshd
```

> **TEST IN A SEPARATE TERMINAL.** Do NOT close your current SSH session until login is confirmed.

### 3.12. SELinux Network Policy

After the first SSH login attempt, generate and load SELinux policy:

```bash
ausearch -c 'pam-keycloak-' --raw | audit2allow -M pam-keycloak-oidc-allow
semodule -i pam-keycloak-oidc-allow.pp

ausearch -c 'sshd' --raw | audit2allow -M sshd-pam-keycloak
semodule -i sshd-pam-keycloak.pp
```

### 3.13. Create Local User Accounts

Username must match the Keycloak username.

```bash
useradd -m username
usermod -aG wheel username  # only if sudo access needed
```

---

## 4. YubiKey PIV Fallback (Emergency SSH Access)

When Keycloak is down, admins authenticate using YubiKey PIV hardware keys via SSH publickey. The private key never leaves the YubiKey.

### 4.1. Server - Service Account

On each Linux server:

```bash
useradd -m svc-admin
usermod -aG wheel svc-admin

mkdir -p /home/svc-admin/.ssh
chmod 700 /home/svc-admin/.ssh
touch /home/svc-admin/.ssh/authorized_keys
chmod 600 /home/svc-admin/.ssh/authorized_keys
chown -R svc-admin:svc-admin /home/svc-admin/.ssh
```

Passwordless sudo (account is already protected by PIV PIN + physical key touch):

```bash
# visudo /etc/sudoers.d/svc-admin
svc-admin ALL=(ALL) NOPASSWD: ALL
```

### 4.2. Client (Windows) - Install Yubico PIV Tool

Download MSI from: https://developers.yubico.com/yubico-piv-tool/Releases/

This installs `yubico-piv-tool.exe` (CLI) and `libykcs11.dll` (PKCS#11 library for OpenSSH).
Default path: `C:\Program Files\Yubico\Yubico PIV Tool\bin\`

Add to system PATH:

```powershell
# PowerShell (as admin) - permanent:
[Environment]::SetEnvironmentVariable("Path",
  $env:Path + ";C:\Program Files\Yubico\Yubico PIV Tool\bin", "Machine")
```

### 4.3. Provision YubiKey

Plug in YubiKey. Run in CMD or PowerShell.

**Generate RSA 2048 key in PIV slot 9a:**

```cmd
"C:\Program Files\Yubico\Yubico PIV Tool\bin\yubico-piv-tool.exe" ^
  -s9a -agenerate -ARSA2048 ^
  --pin-policy=never --touch-policy=always ^
  -o public.pem
```

**Create self-signed certificate (touch YubiKey when it blinks!):**

```cmd
"C:\Program Files\Yubico\Yubico PIV Tool\bin\yubico-piv-tool.exe" ^
  -averify-pin -P123456 ^
  -aselfsign-certificate ^
  -s9a -S "/CN=admin-primary/" ^
  -i public.pem -o cert.pem
```

**Import certificate to YubiKey:**

```cmd
"C:\Program Files\Yubico\Yubico PIV Tool\bin\yubico-piv-tool.exe" -aimport-certificate -s9a -i cert.pem
```

**Export SSH public key:**

```cmd
set PATH=%PATH%;C:\Program Files\Yubico\Yubico PIV Tool\bin
ssh-keygen -D libykcs11.dll -e
```

This outputs two keys - use the **first one** ("Public key for PIV Authentication"). Add it to `authorized_keys` on each server:

```bash
echo "ssh-rsa AAAAB3..." >> /home/svc-admin/.ssh/authorized_keys
```

> Register TWO YubiKeys per admin (primary + backup). Each generates an independent key pair. Both public keys go into `authorized_keys`.

### 4.4. Client - SSH Config

Add to `%USERPROFILE%\.ssh\config` (emergency entry MUST be BEFORE the wildcard):

```
# === Emergency PIV access (YubiKey only, no Keycloak prompts) ===
Host server01-emergency
  HostName server01.example.local
  User svc-admin
  PreferredAuthentications publickey
  PKCS11Provider "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"

# === Normal access (Keycloak first, PIV fallback) ===
Host *.example.local
  PKCS11Provider "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"
  PreferredAuthentications keyboard-interactive,publickey
```

**Usage:**
- Daily login (Keycloak): `ssh user@server01.example.local` -> password + OTP prompt
- Emergency login (PIV): `ssh server01-emergency` -> touch YubiKey only

### 4.5. Optional - Cache PIN with ssh-agent

```powershell
# PowerShell (as admin) - one-time:
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent

# Add PKCS#11 key (once per session - asks for PIN):
ssh-add -s "C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
```

After adding, `ssh server01-emergency` requires only physical touch (no PIN prompt).

### 4.6. Break-Glass Key (last resort)

For when both YubiKeys are lost AND Keycloak is down:

```bash
ssh-keygen -t ed25519 -f /secure-offline-storage/break-glass-key \
  -C "EMERGENCY-ONLY-$(date +%Y%m%d)"

echo "ssh-ed25519 AAAA..." >> /home/svc-admin/.ssh/authorized_keys
```

Store the private key OFFLINE only (printed paper in safe, encrypted USB in separate location). Never on a network-connected device.

---

## 5. User Onboarding

### 5.1. In Keycloak

1. **Users -> Add user** -> fill in details
2. **Credentials -> Set password** (Temporary: Off)
3. **Required user actions:** Configure OTP
4. **Groups -> Join Group** -> appropriate group

### 5.2. On Each Linux Server

```bash
useradd -m username
usermod -aG wheel username  # only for sudo
```

### 5.3. User Self-Service

1. Open `https://keycloak.example.local/realms/REALM/account`
2. Log in -> Keycloak shows OTP setup screen with QR code
3. Scan with Microsoft Authenticator (or any TOTP app)
4. Enter 6-digit verification code

### 5.4. SSH Login

```bash
ssh username@server.example.local
# Password prompt: MyPassword847291
#                  ^^^^^^^^^^^^^^^^
#                  password + 6-digit OTP concatenated (no separator)
```

---

## 6. Rollback

If anything breaks - restore original PAM config:

```bash
cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
systemctl restart sshd
```

---

## 7. Quick Reference - Files on Linux Server

| File | Purpose | Permissions |
|---|---|---|
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc` | PAM binary (modified fork with JWKS) | 755 |
| `/opt/pam-keycloak-oidc/pam-keycloak-oidc.tml` | Config (scope, role, endpoints, secret) | 600 |
| `/opt/pam-keycloak-oidc/check-keycloak-health.sh` | Health check script | 755 |
| `/opt/pam-keycloak-oidc/test_token.sh` | Test script for quick role validation | 755 |
| `/etc/pam.d/sshd` | PAM stack for SSH | - |
| `/etc/pam.d/sudo` | PAM stack for sudo | - |
| `/etc/ssh/sshd_config` | SSHD config (AuthenticationMethods) | - |
| `/var/log/pam-keycloak-oidc.log` | Module log | 664 |
| `~svc-admin/.ssh/authorized_keys` | PIV + break-glass public keys | 600 |
| `/etc/sudoers.d/svc-admin` | NOPASSWD sudo for service account | 440 |

All files in `/opt/pam-keycloak-oidc/` must have SELinux context `bin_t`.
