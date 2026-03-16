#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/_common.sh"

wait_for_keycloak

log "Authenticating admin via kcadm..."
kcadmin config credentials \
  --server "$KC_BASE_URL" \
  --realm master \
  --user "$KC_ADMIN_USER" \
  --password "$KC_ADMIN_PASS"

if ! kcadmin get "realms/$DEMO_REALM" >/dev/null 2>&1; then
  die "Realm '$DEMO_REALM' not found. Run ./demo/setup-realm.sh first."
fi

log "Ensuring test user '$DEMO_USERNAME' exists..."
if kcadmin create users -r "$DEMO_REALM" \
  -s username="$DEMO_USERNAME" \
  -s enabled=true \
  -s email="$DEMO_USERNAME" >/dev/null 2>&1; then
  log "Created user '$DEMO_USERNAME'."
else
  log "User '$DEMO_USERNAME' already exists."
fi

log "Setting password for '$DEMO_USERNAME' ..."
kcadmin set-password \
  -r "$DEMO_REALM" \
  --username "$DEMO_USERNAME" \
  --new-password "$DEMO_PASSWORD" \
  --temporary=false

log "Test user setup completed."
