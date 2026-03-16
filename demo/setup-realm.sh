#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/_common.sh"

start_keycloak
wait_for_keycloak

log "Authenticating admin via kcadm..."
kcadmin config credentials \
  --server "$KC_BASE_URL" \
  --realm master \
  --user "$KC_ADMIN_USER" \
  --password "$KC_ADMIN_PASS"

if kcadmin get "realms/$DEMO_REALM" >/dev/null 2>&1; then
  log "Realm '$DEMO_REALM' already exists. Skipping import."
else
  log "Importing realm from demo/realm.json ..."
  kcadmin create realms -f /opt/keycloak/data/import/oid4vp-demo-realm.json
  log "Realm '$DEMO_REALM' created."
fi

log "Realm setup completed."
