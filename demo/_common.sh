#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DEMO_DIR/.." && pwd)"

# ---- Logging (adapted from oid4vci-deployment helper.sh) ----
if [ -t 1 ]; then
  RED="$(printf '\033[0;31m')"
  GREEN="$(printf '\033[0;32m')"
  YELLOW="$(printf '\033[1;33m')"
  CYAN="$(printf '\033[0;36m')"
  NC="$(printf '\033[0m')"
else
  RED=""; GREEN=""; YELLOW=""; CYAN=""; NC="";
fi

log() { printf "\n${CYAN}[INFO]${NC} %s\n" "$*"; }
warn() { printf "\n${YELLOW}[WARN]${NC} %s\n" "$*" >&2; }
die() { printf "\n${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }

# ---- Defaults ----
DEMO_COMPOSE_PROJECT="${DEMO_COMPOSE_PROJECT:-oid4vp-demo}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.4}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
KC_HTTP_PORT="${KC_HTTP_PORT:-8080}"
KC_BASE_URL="${KC_BASE_URL:-http://localhost:${KC_HTTP_PORT}}"

DEMO_REALM="${DEMO_REALM:-oid4vp-demo}"
DEMO_CLIENT_ID="${DEMO_CLIENT_ID:-test-app}"
DEMO_CLIENT_SECRET="${DEMO_CLIENT_SECRET:-password}"
DEMO_REDIRECT_URI="${DEMO_REDIRECT_URI:-http://localhost:4200/callback}"
DEMO_USERNAME="${DEMO_USERNAME:-test-user@localhost}"
DEMO_PASSWORD="${DEMO_PASSWORD:-password}"
DEMO_VCT="${DEMO_VCT:-https://credentials.example.com/identity_credential}"
DEMO_ISSUER_JWK="${DEMO_ISSUER_JWK:-$DEMO_DIR/keys/keycloak.json}"
DEMO_HOLDER_JWK="${DEMO_HOLDER_JWK:-$DEMO_DIR/keys/user-wallet-key.json}"

export DEMO_COMPOSE_PROJECT KEYCLOAK_IMAGE KC_ADMIN_USER KC_ADMIN_PASS KC_HTTP_PORT KC_BASE_URL
export DEMO_REALM DEMO_CLIENT_ID DEMO_CLIENT_SECRET DEMO_REDIRECT_URI DEMO_USERNAME DEMO_PASSWORD
export DEMO_VCT DEMO_ISSUER_JWK DEMO_HOLDER_JWK

# ---- Docker Compose Detection (adapted from oid4vci-deployment helper.sh) ----
detect_docker_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  else
    die "Neither 'docker compose' nor 'docker-compose' is installed."
  fi
}

compose() {
  local dc
  dc="$(detect_docker_compose)"
  if [[ "$dc" == "docker compose" ]]; then
    docker compose -f "$DEMO_DIR/docker-compose.yml" -p "$DEMO_COMPOSE_PROJECT" "$@"
  else
    docker-compose -f "$DEMO_DIR/docker-compose.yml" -p "$DEMO_COMPOSE_PROJECT" "$@"
  fi
}

find_plugin_jar() {
  local jar
  jar=$(ls "$ROOT_DIR"/target/keycloak-oid4vp-plugin-*.jar 2>/dev/null | \
    grep -vE '(-sources|-javadoc)\\.jar$' | head -n 1 || true)
  if [[ -n "$jar" ]]; then
    echo "$jar"
  fi
}

ensure_plugin_jar() {
  if [[ -n "${PLUGIN_JAR:-}" && -f "$PLUGIN_JAR" ]]; then
    log "Using plugin jar: $PLUGIN_JAR"
    return 0
  fi

  local jar
  jar="$(find_plugin_jar || true)"
  if [[ -z "$jar" ]]; then
    log "Plugin jar not found. Building with Maven wrapper..."
    (cd "$ROOT_DIR" && ./mvnw -q -DskipTests package)
    jar="$(find_plugin_jar || true)"
  fi

  if [[ -z "$jar" ]]; then
    die "Plugin jar not found after build. Expected under $ROOT_DIR/target."
  fi

  export PLUGIN_JAR="$jar"
  log "Using plugin jar: $PLUGIN_JAR"
}

start_keycloak() {
  ensure_plugin_jar
  log "Starting Keycloak via Docker Compose (project: $DEMO_COMPOSE_PROJECT)..."
  compose up -d
}

wait_for_keycloak() {
  local attempts=60
  local wait_secs=2

  log "Waiting for Keycloak at $KC_BASE_URL ..."
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "$KC_BASE_URL/realms/master" >/dev/null 2>&1; then
      log "Keycloak is ready."
      return 0
    fi
    sleep "$wait_secs"
  done

  die "Keycloak did not become ready after $((attempts * wait_secs)) seconds."
}

kcadmin() {
  compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"
}
