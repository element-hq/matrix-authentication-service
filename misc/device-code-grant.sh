#!/bin/sh

set -eu

usage() {
  echo "$0 [synapse-url] <scope>..." >&2
  exit 1
}

req() {
  METHOD="$1"
  shift
  URL="$1"
  shift
  printf "> %4s %s\n" "$METHOD" "$URL" >&2
  curl -sL --fail-with-body -o- -H 'Accept: application/json' -X "$METHOD" "$@" "$URL"
}

if [ "$#" -eq "0" ]; then
  usage
fi

CS_API="${1%/}"
shift

if [ -z "$*" ]; then
  SCOPE="urn:matrix:org.matrix.msc2967.client:api:*"
else
  SCOPE="$*"
fi


echo "Discovering the homeserver endpoints"
METADATA="$(req GET "${CS_API}/_matrix/client/unstable/org.matrix.msc2965/auth_metadata")"
DEVICE_AUTHORIZATION_ENDPOINT="$(echo "$METADATA" | jq -r '.device_authorization_endpoint')"
TOKEN_ENDPOINT="$(echo "$METADATA" | jq -r '.token_endpoint')"
REGISTRATION_ENDPOINT="$(echo "$METADATA" | jq -r '.registration_endpoint')"

echo "Registering the client"
# Note that the client_uri is only used as an identifier, MAS will not try to contact this URI
RESP="$(
  req POST "${REGISTRATION_ENDPOINT}" \
    -H 'Content-Type: application/json' \
    -d @- <<EOF
{
  "client_name": "CLI tool",
  "client_uri": "https://github.com/element-hq/matrix-authentication-service/",
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
  "application_type": "native",
  "token_endpoint_auth_method": "none"
}
EOF
)"

CLIENT_ID="$(echo "$RESP" | jq -r '.client_id')"

DEVICE_GRANT="$(
  req POST "${DEVICE_AUTHORIZATION_ENDPOINT}" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "scope=${SCOPE}"
)"

cat - <<EOF
-----------------------
            Homeserver: ${CS_API}
 Registration endpoint: ${REGISTRATION_ENDPOINT}
  Device auth endpoint: ${DEVICE_AUTHORIZATION_ENDPOINT}
        Token endpoint: ${TOKEN_ENDPOINT}
             Client ID: ${CLIENT_ID}
                 Scope: ${SCOPE}
-----------------------
EOF

echo
echo "Open the following URL in your browser:"
echo "$DEVICE_GRANT" | jq -r ".verification_uri_complete"
echo

# If we have qrencode
if command -v qrencode 2>/dev/null; then
  echo "$DEVICE_GRANT" | jq -r ".verification_uri_complete" | qrencode -t ANSI256UTF8
  echo
fi

echo "Alternatively, go to $(echo "$DEVICE_GRANT" | jq -r ".verification_uri") and enter the code $(echo "$DEVICE_GRANT" | jq -r ".user_code")"
echo
echo -----------------------
echo

DEVICE_CODE="$(echo "$DEVICE_GRANT" | jq -r ".device_code")"
INTERVAL="$(echo "$DEVICE_GRANT" | jq -r ".interval")"

while true; do
  DEVICE_RESP="$(
    req POST "${TOKEN_ENDPOINT}" \
      --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
      --data-urlencode "device_code=${DEVICE_CODE}" \
      --data-urlencode "client_id=${CLIENT_ID}" || true
  )"
  if [ "$(echo "$DEVICE_RESP" | jq -r ".error")" = "authorization_pending" ]; then
    echo "Waiting for authorization"
    sleep "${INTERVAL}"
  else
    break
  fi
done

echo "$DEVICE_RESP" | jq .

exit 0
