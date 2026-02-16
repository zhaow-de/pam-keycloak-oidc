#!/usr/bin/env bash
# Test script for Keycloak OIDC + PAM authentication flow.
#
# 1. Fetches an access token from Keycloak (password grant)
# 2. Decodes the JWT payload to inspect ssh_roles / realm_access
# 3. Pipes credentials into pam-keycloak-oidc to simulate a PAM login
#
# Works best *before* enabling 2FA on the test account - otherwise
# the TOTP code is consumed during token fetch and you need to wait
# for a new code window before the PAM step.
# (Alternatively, enable reusable TOTP codes in Keycloak for testing.)
#
# Requires: curl, jq, base64, /opt/pam-keycloak-oidc/pam-keycloak-oidc
set +H # Disable bash history expansion so '!' in passwords doesn't cause issues

CLIENT_ID="YOUR_CLIENT_ID"
CLIENT_SECRET="YOUR_CLIENT_SECRET"

KC_USER="testuser"
KC_PASSWORD='test123'

KC_URL="https://keycloak.example.local/realms/REALM/protocol/openid-connect/token"

# OAuth2 scopes; "ssh_roles" is the custom **Client scope** set in Keycloak
# "ssh_roles" is also used by jq for parsing (change the value in line :56)
SCOPE="openid ssh_roles"

USE_TOTP=0
KC_TOTP="000000"

if [ $USE_TOTP -eq 0 ]; then
        # Get token without OTP
        TOKEN=$(curl -sk -X POST \
          "$KC_URL" \
          -d "grant_type=password" \
          -d "client_id=$CLIENT_ID" \
          -d "client_secret=$CLIENT_SECRET" \
          -d "username=$KC_USER" \
          -d "password=$KC_PASSWORD" \
          -d "scope=$SCOPE" | jq -r '.access_token')
else
        # Get token with OTP
        TOKEN=$(curl -sk -X POST \
          "$KC_URL" \
          -d "grant_type=password" \
          -d "client_id=$CLIENT_ID" \
          -d "client_secret=$CLIENT_SECRET" \
          -d "username=$KC_USER" \
          -d "password=$KC_PASSWORD" \
          -d "totp=$KC_TOTP" \
          -d "scope=$SCOPE" | jq -r '.access_token')
fi

# Decode the payload (beware of the base64url encoding)
echo $TOKEN | cut -d. -f2 | tr '_-' '/+' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d | jq '{ssh_roles, realm_access}'

# echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

export PAM_USER=$KC_USER

if [ $USE_TOTP -eq 0 ]; then
        echo "$KC_PASSWORD" | /opt/pam-keycloak-oidc/pam-keycloak-oidc
else
        echo ""
        echo ">>> OTP was consumed during token fetch."
        # Uncomment the following lines to automatically wait for a new TOTP window
        # echo ">>> Waiting for new TOTP window (max 30s)..."
        # sleep 31
        echo ">>> Please enter a new TOTP code (wait for a new code):"
        read -r KC_TOTP
        echo "$KC_PASSWORD$KC_TOTP" | /opt/pam-keycloak-oidc/pam-keycloak-oidc
fi
