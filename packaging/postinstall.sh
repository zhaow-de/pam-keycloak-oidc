#!/bin/bash
# Runs after RPM/DEB install. Everything here is best-effort: a failure must not
# leave the package half-installed, so each step swallows its own errors.
set -e

PKG_DIR="/opt/pam-keycloak-oidc"
LOG_FILE="/var/log/pam-keycloak-oidc.log"

# sshd_t may only execute files labelled bin_t. Without this the PAM stack fails
# with a permission denial that looks nothing like a labelling problem.
if command -v chcon >/dev/null 2>&1 && command -v getenforce >/dev/null 2>&1; then
    if [ "$(getenforce 2>/dev/null || echo Disabled)" != "Disabled" ]; then
        chcon -t bin_t "${PKG_DIR}/pam-keycloak-oidc"        2>/dev/null || true
        chcon -t bin_t "${PKG_DIR}/pam-keycloak-oidc.tml"    2>/dev/null || true
        chcon -t bin_t "${PKG_DIR}/check-keycloak-health.sh" 2>/dev/null || true
        echo "[pam-keycloak-oidc] SELinux: bin_t context set on package files"
    fi
fi

# The config carries the client secret.
chmod 0600 "${PKG_DIR}/pam-keycloak-oidc.tml" 2>/dev/null || true
# test_token.sh carries test credentials; keep it root-only.
chmod 0700 "${PKG_DIR}/test_token.sh" 2>/dev/null || true

if [ ! -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    chmod 0664 "$LOG_FILE"
    command -v restorecon >/dev/null 2>&1 && restorecon "$LOG_FILE" 2>/dev/null || true
fi

cat <<BANNER

============================================================
 pam-keycloak-oidc installed to ${PKG_DIR}/
============================================================

 Next:
   1. Edit ${PKG_DIR}/pam-keycloak-oidc.tml
      client-secret, vpn-user-role, the four endpoints, xor-key
   2. Edit ${PKG_DIR}/check-keycloak-health.sh -- KC_URL and KC_REALM
   3. Trust the Keycloak CA, then configure /etc/pam.d/sshd and sshd_config

 Full instructions:
   https://zhaow-de.github.io/pam-keycloak-oidc/deployment/

 Log file: ${LOG_FILE}

 WARNING: never run 'restorecon -Rv' on ${PKG_DIR}/ -- it resets the
 context to usr_t and SSH authentication stops working.
============================================================

BANNER
