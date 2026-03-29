#!/bin/bash
# End-to-end test: logs in via Keycloak and calls the issuer lambda to obtain a VC.
# Requires: curl, jq, python3
set -uo pipefail

KEYCLOAK="https://keycloak.zeroverify.net"
REALM="zeroverify"
CLIENT_ID="zeroverify-wallet"
REDIRECT_URI="https://wallet.zeroverify.net/callback"
IDP_HINT="mock-idp"
ISSUER_API="${ISSUER_API:-https://gw.api.zeroverify.net}"

# Generate PKCE pair
read -r verifier challenge < <(python3 -c "
import base64, hashlib, os
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print(v, c)
")

echo ""
echo "=== Step 1: Log OUT any active Keycloak session first ==="
echo ""
echo "${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/logout?client_id=${CLIENT_ID}&post_logout_redirect_uri=${REDIRECT_URI}"
echo ""
read -rp "Press Enter once logged out (or if no session was active)..."

echo ""
echo "=== Step 2: Open the login URL in your browser ==="
echo ""
echo "${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/auth?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid&code_challenge=${challenge}&code_challenge_method=S256&kc_idp_hint=${IDP_HINT}"
echo ""
echo "Log in with:  testuser / password"
echo ""
echo "=== Step 3: Paste the full callback URL (the browser will 404 — that's fine) ==="
echo ""
read -rp "Paste here: " input

# Extract code from either a full URL or raw code value
if [[ "$input" == http* ]]; then
  code=$(echo "$input" | grep -oP '(?<=code=)[^&]+')
else
  code="$input"
fi

echo ""
echo "=== Calling issuer lambda... ==="
echo ""

curl -X POST "${ISSUER_API}/api/v1/credentials/issue" \
  -H "Content-Type: application/json" \
  -d "{\"authorization_code\": \"${code}\", \"code_verifier\": \"${verifier}\"}" \
  | jq .
