#!/usr/bin/env bash
# Fetch a token from Keycloak, decode the roles claim, then drive the module the
# way PAM does. Useful for telling "the realm is misconfigured" apart from "the
# PAM stack is misconfigured" before touching /etc/pam.d.
#
# Holds test credentials, so it installs 0700 and must stay root-only.
#
# Needs: curl, jq. Run BEFORE enabling OTP on the test account, or the code is
# consumed by the token request and the PAM step needs a fresh one.
set +H  # keep '!' in passwords from triggering history expansion

CLIENT_ID="demo-pam"
CLIENT_SECRET="CHANGE_ME"

KC_USER="testuser"
KC_PASSWORD='CHANGE_ME'

KC_URL="https://keycloak.example.com/realms/demo-pam/protocol/openid-connect/token"

# The custom client scope; also the claim the module reads roles from.
SCOPE="openid pam_roles"
ROLE_CLAIM="pam_roles"

USE_TOTP=0
KC_TOTP="000000"

request_token() {
    local extra=()
    [ "$USE_TOTP" -eq 1 ] && extra=(-d "totp=$KC_TOTP")
    curl -s -X POST "$KC_URL" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "username=$KC_USER" \
        -d "password=$KC_PASSWORD" \
        -d "scope=$SCOPE" \
        "${extra[@]}" | jq -r '.access_token'
}

TOKEN=$(request_token)
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "No access token returned. Check client-id, client-secret and that the" >&2
    echo "client has 'Direct access grants' enabled." >&2
    exit 1
fi

# The payload is base64url and unpadded; translate the alphabet and re-pad.
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' \
    | awk '{while(length%4)$0=$0"=";print}' | base64 -d \
    | jq "{$ROLE_CLAIM, realm_access, iss, aud, exp}"

export PAM_USER="$KC_USER"
if [ "$USE_TOTP" -eq 0 ]; then
    echo "$KC_PASSWORD" | /opt/pam-keycloak-oidc/pam-keycloak-oidc
else
    echo
    echo "The OTP was consumed fetching the token above. Enter a fresh one:"
    read -r KC_TOTP
    echo "${KC_PASSWORD}${KC_TOTP}" | /opt/pam-keycloak-oidc/pam-keycloak-oidc
fi
