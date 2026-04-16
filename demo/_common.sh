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

DEMO_ENV_FILE="${DEMO_ENV_FILE:-$DEMO_DIR/.env}"
if [[ -f "$DEMO_ENV_FILE" ]]; then
  log "Loading demo config from $DEMO_ENV_FILE"
  set -a
  # shellcheck source=/dev/null
  source "$DEMO_ENV_FILE"
  set +a
fi

# ---- Defaults ----
DEMO_COMPOSE_PROJECT="${DEMO_COMPOSE_PROJECT:-oid4vp-demo}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.6.1}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
KC_HTTP_PORT="${KC_HTTP_PORT:-18080}"
KC_BASE_URL="${KC_BASE_URL:-http://localhost:${KC_HTTP_PORT}}"
KC_ADMIN_SERVER_URL="${KC_ADMIN_SERVER_URL:-http://localhost:8080}"

DEMO_REALM="${DEMO_REALM:-oid4vp-demo}"
DEMO_CLIENT_ID="${DEMO_CLIENT_ID:-test-app}"
DEMO_CLIENT_SECRET="${DEMO_CLIENT_SECRET:-password}"
DEMO_ALICE_USERNAME="${DEMO_ALICE_USERNAME:-alice@localhost}"
DEMO_BOB_USERNAME="${DEMO_BOB_USERNAME:-bob@localhost}"
DEMO_UNKNOWN_USERNAME="${DEMO_UNKNOWN_USERNAME:-mallory@localhost}"
DEMO_VCT="${DEMO_VCT:-https://credentials.example.com/identity_credential}"
DEMO_ISSUER_JWK="${DEMO_ISSUER_JWK:-$DEMO_DIR/keys/keycloak.json}"
DEMO_HOLDER_JWK="${DEMO_HOLDER_JWK:-$DEMO_DIR/keys/user-wallet-key.json}"
DEMO_CLASSPATH_FILE="${DEMO_CLASSPATH_FILE:-$DEMO_DIR/target/demo.classpath}"
DEMO_CLASSES_DIR="${DEMO_CLASSES_DIR:-$DEMO_DIR/target/classes}"

export DEMO_COMPOSE_PROJECT KEYCLOAK_IMAGE KC_ADMIN_USER KC_ADMIN_PASS KC_HTTP_PORT KC_BASE_URL KC_ADMIN_SERVER_URL
export DEMO_REALM DEMO_CLIENT_ID DEMO_CLIENT_SECRET
export DEMO_ALICE_USERNAME DEMO_BOB_USERNAME DEMO_UNKNOWN_USERNAME
export DEMO_VCT DEMO_ISSUER_JWK DEMO_HOLDER_JWK DEMO_CLASSPATH_FILE DEMO_CLASSES_DIR

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
  for jar in "$ROOT_DIR"/target/keycloak-oid4vp-plugin-*.jar; do
    [[ -e "$jar" ]] || continue
    case "$jar" in
      *-sources.jar|*-javadoc.jar) continue ;;
    esac
    echo "$jar"
    return 0
  done
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

authenticate_admin() {
  log "Authenticating admin via kcadm..."
  kcadmin config credentials \
    --server "$KC_ADMIN_SERVER_URL" \
    --realm master \
    --user "$KC_ADMIN_USER" \
    --password "$KC_ADMIN_PASS"
}

ensure_demo_realm() {
  start_keycloak
  wait_for_keycloak
  authenticate_admin

  if kcadmin get "realms/$DEMO_REALM" >/dev/null 2>&1; then
    log "Realm '$DEMO_REALM' already exists. Reusing it."
    warn "If this realm was created by an older demo version, run 'just stop' for a clean reset."
  else
    log "Importing realm from demo/realm.json ..."
    kcadmin create realms -f /opt/keycloak/data/import/oid4vp-demo-realm.json
    log "Realm '$DEMO_REALM' created."
  fi

  log "Demo realm is ready."
  log "Imported demo users: $DEMO_ALICE_USERNAME, $DEMO_BOB_USERNAME"
}

build_demo_classpath() {
  ensure_plugin_jar
  mkdir -p "$(dirname "$DEMO_CLASSPATH_FILE")"

  log "Building demo classpath..."
  (
    cd "$ROOT_DIR"
    ./mvnw -q -DskipTests \
      -Dmdep.includeScope=provided \
      -Dmdep.outputFile="$DEMO_CLASSPATH_FILE" \
      dependency:build-classpath
  )

  [[ -f "$DEMO_CLASSPATH_FILE" ]] || die "Failed to build classpath at $DEMO_CLASSPATH_FILE"
}

demo_source_files() {
  find "$DEMO_DIR/app" "$DEMO_DIR/lib" "$DEMO_DIR/smoke" "$DEMO_DIR/wallet" -name '*.java' | sort
}

compile_demo_sources() {
  build_demo_classpath
  mkdir -p "$DEMO_CLASSES_DIR"

  mapfile -t demo_sources < <(demo_source_files)
  [[ ${#demo_sources[@]} -gt 0 ]] || die "No demo Java sources found."

  local classpath
  classpath="$(cat "$DEMO_CLASSPATH_FILE"):$ROOT_DIR/target/classes"

  log "Compiling demo Java sources..."
  javac -cp "$classpath" -d "$DEMO_CLASSES_DIR" "${demo_sources[@]}"
}

demo_runtime_classpath() {
  [[ -f "$DEMO_CLASSPATH_FILE" ]] || build_demo_classpath
  printf '%s:%s:%s' "$(cat "$DEMO_CLASSPATH_FILE")" "$ROOT_DIR/target/classes" "$DEMO_CLASSES_DIR"
}

run_demo_java() {
  local class_name="$1"
  shift
  compile_demo_sources
  export DEMO_BASE_URL="$KC_BASE_URL"
  java -cp "$(demo_runtime_classpath)" "$class_name" "$@"
}
