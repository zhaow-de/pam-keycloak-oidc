---
weight: 50
title: "YubiKey PIV fallback"
---

# YubiKey PIV fallback

Making SSH depend on Keycloak means an outage of the identity provider is an outage of your ability
to log in and fix it. This page sets up a second, entirely independent path: SSH public-key
authentication backed by a YubiKey in PIV mode, where the private key never leaves the hardware.

It pairs with the sshd configuration in [production deployment](../deployment):

```
AuthenticationMethods publickey keyboard-interactive:pam
```

The space means *or*. Normal logins take `keyboard-interactive` and go through Keycloak; when the
health check reports Keycloak down, PAM fails fast and SSH falls through to `publickey`.

> [!NOTE]
> Provision and test this **before** you switch SSH over to Keycloak. A fallback verified for the
> first time during an outage is not a fallback.

## 1. Service account on each server

The fallback logs in as a dedicated account rather than as an end user, so it works even when no
Keycloak identity resolves:

```shell
useradd -m svc-admin
usermod -aG wheel svc-admin

mkdir -p /home/svc-admin/.ssh
chmod 700 /home/svc-admin/.ssh
touch /home/svc-admin/.ssh/authorized_keys
chmod 600 /home/svc-admin/.ssh/authorized_keys
chown -R svc-admin:svc-admin /home/svc-admin/.ssh
```

Passwordless sudo is appropriate here — the account is already gated by the YubiKey's PIN and a
physical touch, and the usual password fallback is exactly what is unavailable during an outage:

```shell
# visudo /etc/sudoers.d/svc-admin
svc-admin ALL=(ALL) NOPASSWD: ALL
```

## 2. Client tooling

Install the [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/Releases/). It provides
`yubico-piv-tool` and the PKCS#11 library OpenSSH talks to (`libykcs11`). On Windows both land in
`C:\Program Files\Yubico\Yubico PIV Tool\bin\`:

```powershell
[Environment]::SetEnvironmentVariable("Path",
  $env:Path + ";C:\Program Files\Yubico\Yubico PIV Tool\bin", "Machine")
```

## 3. Provision the key

Generate a key pair in PIV slot `9a`. `--touch-policy=always` means every authentication needs a
physical touch, so a compromised client cannot use the key unattended:

```shell
yubico-piv-tool -s9a -agenerate -ARSA2048 \
  --pin-policy=never --touch-policy=always -o public.pem
```

Self-sign a certificate for it — the YubiKey needs one in the slot. It blinks; touch it:

```shell
yubico-piv-tool -averify-pin -P123456 -aselfsign-certificate \
  -s9a -S "/CN=admin-primary/" -i public.pem -o cert.pem

yubico-piv-tool -aimport-certificate -s9a -i cert.pem
```

Export the SSH public key. Two keys are printed; the first, *Public key for PIV Authentication*, is
the one to use:

```shell
ssh-keygen -D libykcs11.dll -e
```

Append it to `authorized_keys` on every server:

```shell
echo "ssh-rsa AAAAB3..." >> /home/svc-admin/.ssh/authorized_keys
```

> [!NOTE]
> Provision **two** YubiKeys per administrator, a primary and a spare. They generate independent key
> pairs, so both public keys go into `authorized_keys`. A single key is a single point of failure
> standing behind your other single point of failure.

## 4. Client SSH configuration

In `~/.ssh/config` — the emergency entry must come **before** the wildcard, since OpenSSH takes the
first match for each option:

```
# Emergency access: YubiKey only, no Keycloak prompt
Host server01-emergency
  HostName server01.example.com
  User svc-admin
  PreferredAuthentications publickey
  PKCS11Provider "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"

# Normal access: Keycloak first, PIV as fallback
Host *.example.com
  PKCS11Provider "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"
  PreferredAuthentications keyboard-interactive,publickey
```

Day to day, `ssh user@server01.example.com` prompts for password plus OTP. During an outage,
`ssh server01-emergency` asks only for the touch.

## 5. Caching the PIN (optional)

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent

ssh-add -s "C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
```

Once loaded, the emergency host needs only the physical touch for the rest of the session.

## 6. Break-glass key

For the case where both YubiKeys are gone *and* Keycloak is down:

```shell
ssh-keygen -t ed25519 -f break-glass-key -C "EMERGENCY-ONLY-20260830"
echo "ssh-ed25519 AAAA..." >> /home/svc-admin/.ssh/authorized_keys
```

Keep the private key offline and only offline — printed and in a safe, or on an encrypted drive
stored somewhere other than the machines it opens. A break-glass key on a network-connected device
is just a second credential to steal.
