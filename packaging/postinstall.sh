#!/bin/bash
# Post-install script for pam-keycloak-oidc package
# Runs after RPM/DEB installation

set -e

PKG_DIR="/opt/pam-keycloak-oidc"
LOG_FILE="/var/log/pam-keycloak-oidc.log"

# --- SELinux context (required on RHEL/OL/Rocky/Alma) ---
# Binary, config, and health check must have bin_t context
# so SELinux allows sshd_t to execute them.
if command -v chcon &>/dev/null && command -v getenforce &>/dev/null; then
    SE_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
    if [ "$SE_STATUS" != "Disabled" ]; then
        chcon -t bin_t "${PKG_DIR}/pam-keycloak-oidc"          2>/dev/null || true
        chcon -t bin_t "${PKG_DIR}/pam-keycloak-oidc.tml"      2>/dev/null || true
        chcon -t bin_t "${PKG_DIR}/check-keycloak-health.sh"   2>/dev/null || true
        echo "[pam-keycloak-oidc] SELinux: set bin_t context on package files"
    fi
fi

# --- Config file permissions (contains client secret) ---
chmod 0600 "${PKG_DIR}/pam-keycloak-oidc.tml" 2>/dev/null || true

# --- Log file ---
if [ ! -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    chmod 0664 "$LOG_FILE"
    # Restore default SELinux context for /var/log
    if command -v restorecon &>/dev/null; then
        restorecon -v "$LOG_FILE" 2>/dev/null || true
    fi
fi

# --- Post-install message ---
echo ""
echo "============================================================"
echo " pam-keycloak-oidc installed to ${PKG_DIR}/"
echo "============================================================"
echo ""
echo " Next steps:"
echo "   1. Edit config:  vi ${PKG_DIR}/pam-keycloak-oidc.tml"
echo "      - Set client-secret, vpn-user-role, endpoints"
echo "      - Reference: ${PKG_DIR}/pam-keycloak-oidc.tml.example"
echo ""
echo "   2. Edit health check: vi ${PKG_DIR}/check-keycloak-health.sh"
echo "      - Set KC_URL and KC_REALM"
echo ""
echo "   3. Import Keycloak CA certificate:"
echo "      update-ca-trust  (after placing cert in /etc/pki/ca-trust/source/anchors/)"
echo ""
echo "   4. Configure PAM (/etc/pam.d/sshd) and SSHD"
echo "      See project documentation for PAM stack configuration."
echo ""
echo "   5. After first SSH login, generate SELinux policy if needed:"
echo "      ausearch -c 'pam-keycloak-' --raw | audit2allow -M pam-keycloak-oidc-allow"
echo "      semodule -i pam-keycloak-oidc-allow.pp"
echo ""
echo " Log file: ${LOG_FILE}"
echo " WARNING: Do NOT run restorecon on ${PKG_DIR}/ — it resets bin_t context!"
echo "============================================================"
