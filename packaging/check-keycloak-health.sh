#!/bin/bash
# Fast Keycloak reachability check (runs before password prompt)
# Returns 0 if Keycloak is up, non-zero otherwise.
#
# Used by PAM stack: if this script fails, PAM denies immediately
# and SSH falls back to publickey (e.g. YubiKey PIV).
#
# Edit KC_URL and KC_REALM to match your environment.

KC_URL="https://keycloak.example.com"
KC_REALM="master"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 3 --max-time 5 \
    "${KC_URL}/realms/${KC_REALM}/.well-known/openid-configuration" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    exit 0 # Keycloak reachable
fi

logger -t pam-keycloak-oidc "Keycloak unreachable (HTTP: ${HTTP_CODE:-000}), fallback active"
exit 1 # Unreachable -> PAM_SYSTEM_ERR -> default=die in PAM stack
