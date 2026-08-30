#!/bin/bash
# Fast reachability check for Keycloak, run by the PAM stack BEFORE the password
# prompt. Exit 0 means reachable; any other status makes PAM fail immediately so
# SSH can fall through to publickey (see the YubiKey PIV fallback guide).
#
# Without this the same outage costs every login a full token-request timeout.
#
# Edit the two values below to match your realm.

KC_URL="https://keycloak.example.com"
KC_REALM="demo-pam"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 3 --max-time 5 \
    "${KC_URL}/realms/${KC_REALM}/.well-known/openid-configuration" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    exit 0
fi

logger -t pam-keycloak-oidc "Keycloak unreachable (HTTP ${HTTP_CODE:-000}), falling back"
exit 1
