#!/usr/bin/env bash
# Bring up the stack, run the Playwright journey, then tear the stack down.
#   --keep-stack-alive  leave the stack running afterwards (logs under build/)
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$E2E_DIR"

CYAN=$'\033[0;36m'; RED=$'\033[0;31m'; NC=$'\033[0m'
log() { printf '%s[play]%s %s\n' "$CYAN" "$NC" "$*"; }
die() { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

KEEP_STACK_ALIVE=0
for flag in "$@"; do
  case "$flag" in
    --keep-stack-alive) KEEP_STACK_ALIVE=1 ;;
    *) echo "Unknown option: $flag" >&2 && exit 1 ;;
  esac
done

# The setup is idempotent and cheap on re-runs, so every journey starts from
# a consistent state: dependency JARs at the latest releases, realm rendered.
./scripts/setup.sh || {
  die "Setup failed."
}

if [[ -f ".env" ]]; then
  set -a; source ".env"; set +a
fi

# The realm the stack boots with (assets/realm/ renders build/realm.json
# from the same sources of truth).
KEYCLOAK_REALM="oid4vc-vci"
KEYCLOAK_HTTP_PORT="${KEYCLOAK_HTTP_PORT:-18080}"
MOCK_FE_HTTP_PORT="${MOCK_FE_HTTP_PORT:-14200}"
WALLET_HTTP_PORT="${WALLET_HTTP_PORT:-18085}"
# Local-only admin credentials; fixed, because docker-compose.yml seeds the
# same values when bootstrapping Keycloak's admin user.
KEYCLOAK_ADMIN_USER="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"
KEYCLOAK_REALM_URL="http://localhost:${KEYCLOAK_HTTP_PORT}/realms/${KEYCLOAK_REALM}"

compose() { docker compose "$@"; }

# Whenever the script exits with an error, dump the stack logs to
# build/docker-compose.log — the primary evidence for a crashed Keycloak or
# wallet (e.g. "dependency failed to start" in CI).
on_error() {
  if [ $? -ne 0 ]; then
    mkdir -p build
    compose logs > build/docker-compose.log 2>/dev/null || true
  fi
}
trap on_error EXIT

install_npm_deps() {
  if [[ ! -d node_modules ]]; then
    log "Installing dependencies (pnpm install) ..."
    if ! command -v pnpm >/dev/null 2>&1 && command -v corepack >/dev/null 2>&1; then
      corepack enable pnpm
    fi
    pnpm install --frozen-lockfile
  fi
}

compose up -d --wait

log "Waiting for realm $KEYCLOAK_REALM to be ready ..."
for i in $(seq 1 60); do
  if curl -fsS "$KEYCLOAK_REALM_URL" >/dev/null 2>&1; then
    log "Keycloak realm ready."
    break
  fi
  if [ "$i" == 60 ]; then
    die "Realm $KEYCLOAK_REALM not ready after 120s"
  fi
  sleep 2
done

# Read the currently configured credential definitions from the rendered
# realm (client scopes carrying a credential_configuration_id).
configured_credential_scopes() {
  python3 -c '
import json, sys
scope_names = [
    scope["name"]
    for scope in json.load(sys.stdin)["clientScopes"]
    if "vc.credential_configuration_id" in scope.get("attributes", {})
]
print(" ".join(scope_names))' < build/realm.json || die "Could not read the realm's credential scopes"
}

# Per-user VC grants are admin-API only; realm import cannot do this.
# The journey does not depend on every user having every credential, but the
# demo app can then offer issuance for every user without preconfiguration.
admin_access_token() {
  curl -fsS -X POST "http://localhost:${KEYCLOAK_HTTP_PORT}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=${KEYCLOAK_ADMIN_USER}&password=${KEYCLOAK_ADMIN_PASSWORD}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

grant_user_credential() {
  local username="$1" scope_name="$2"
  local admin_token user_id
  admin_token=$(admin_access_token) ||
    die "Could not authenticate as realm admin"
  user_id=$(curl -fsS -H "Authorization: Bearer $admin_token" \
    "http://localhost:${KEYCLOAK_HTTP_PORT}/admin/realms/${KEYCLOAK_REALM}/users?username=$username" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])') ||
    die "Could not find user $username"
  # HTTP 409 simply means the grant already exists — fine for re-runs.
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" \
    -d "{\"credentialScopeName\":\"$scope_name\"}" \
    "http://localhost:${KEYCLOAK_HTTP_PORT}/admin/realms/${KEYCLOAK_REALM}/users/$user_id/vc/credentials")
  if [ "$code" != "200" ] && [ "$code" != "409" ]; then
    die "Granting credential $scope_name to $username failed (HTTP $code)"
  fi
  log "Granted credential $scope_name to $username."
}

list_realm_users() {
  local admin_token
  admin_token=$(admin_access_token)
  curl -fsS -H "Authorization: Bearer $admin_token" \
    "http://localhost:${KEYCLOAK_HTTP_PORT}/admin/realms/${KEYCLOAK_REALM}/users?max=200" |
    python3 -c '
import json, sys
print("\n".join(
    user["username"]
    for user in json.load(sys.stdin)
    if user.get("enabled") and ":" not in user["username"]))' ||
    die "Could not list realm users"
}

# Enable every configured credential for every realm user (the demo app can
# then offer issuance for anyone without preconfiguration).
enabled_credential_scopes=$(configured_credential_scopes)
for username in $(list_realm_users); do
  for scope_name in $enabled_credential_scopes; do
    grant_user_credential "$username" "$scope_name"
  done
done

log "Waiting for the wallet HTTP API to be ready ..."
for i in $(seq 1 60); do
  if curl -fsS "http://localhost:${WALLET_HTTP_PORT}/api/credentials" >/dev/null 2>&1; then
    log "Wallet HTTP API ready."
    break
  fi
  if [ "$i" == 60 ]; then
    die "Wallet HTTP API not ready after 120s"
  fi
  sleep 2
done

log "Running journeys ..."

declare -i FAILED=0
install_npm_deps || FAILED=1
if [[ $FAILED == 0 ]]; then
  pnpm exec playwright test || FAILED=1
fi
EXIT_CODE=$FAILED

log "Tearing stack down ..."
if [ "${E2E_KEEP_STACK:-0}" = "1" ] || [ "$KEEP_STACK_ALIVE" == "1" ]; then
  log "Leaving the stack up (logs: build/docker-compose.log)."
  compose logs > build/docker-compose.log || true
  exit $EXIT_CODE
fi
# On failure, preserve the stack logs before removing the containers — they
# are the primary evidence for a crashed Keycloak or wallet.
if [ "$EXIT_CODE" != 0 ]; then
  mkdir -p build
  compose logs > build/docker-compose.log || true
fi
compose down -v || true

exit $EXIT_CODE
