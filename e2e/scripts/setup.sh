#!/usr/bin/env bash
# Fetches the runtime inputs of the e2e stack — idempotent: re-runs only do
# work when something is missing or a newer upstream release exists.
#   - latest wallet-verifier plugin JAR (this repo, keycloak-oid4vp-plugin)
#   - latest status-list plugin JAR (ADORSYS-GIS/token-status-link)
#   - renders the realm from assets/realm/ into build/realm.json
set -euo pipefail
IFS=$'\n\t'

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$E2E_DIR/build"
PROVIDERS_DIR="$BUILD_DIR/providers"

RED=$'\033[0;31m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
log() { printf '%s[setup]%s %s\n' "$CYAN" "$NC" "$*"; }
die() { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

# Resolve the latest release JAR of <owner/repo> into $PROVIDERS_DIR — or
# skip entirely when the cached JAR still matches the resolved release tag.
fetch_latest_release_jar() {
  local repo="$1" out_name="$2"
  mkdir -p "$PROVIDERS_DIR"
  local json tag version asset marker="$PROVIDERS_DIR/$out_name.latest"
  log "Resolving the latest release of $repo ..."
  json="$(mktemp)"
  curl -fsSL "https://api.github.com/repos/$repo/releases/latest" -o "$json" ||
    die "Could not resolve the latest release of $repo"
  tag="$(sed -nE 's/.*"tag_name": *"([^"]+)".*/\1/p' "$json" | head -1)" ||
    die "Could not resolve the latest release tag of $repo"
  version="${tag#v}"
  asset="https://github.com/$repo/releases/download/$tag/$out_name-$version.jar"

  if [[ -f "$PROVIDERS_DIR/$out_name.jar" && "$(cat "$marker" 2>/dev/null)" == "$tag" ]]; then
    log "Skipping $out_name.jar (already at latest release $tag)."
    printf '  %s -> %s (%s)\n' "$repo" "$out_name.jar" "$version"
    return 0
  fi

  log "Downloading $asset ..."
  local tmp_jar
  tmp_jar="$(mktemp)"
  curl -fL "$asset" -o "$tmp_jar" || die "Download failed: $asset"
  mv "$tmp_jar" "$PROVIDERS_DIR/$out_name.jar"
  # Keycloak's container runs as uid 1000; mktemp files are 0600 and owned by
  # the invoking user (uid 1001 on CI) — unreadable inside the container
  # without a mode fix ("Permission denied" at provider scan).
  chmod 0644 "$PROVIDERS_DIR/$out_name.jar"
  printf '%s\n' "$tag" > "$marker"
  printf '  %s -> %s (%s)\n' "$repo" "$out_name.jar" "$version"
}

fetch_latest_release_jar "ADORSYS-GIS/token-status-link" "keycloak-token-status-plugin"
fetch_latest_release_jar "ADORSYS-GIS/keycloak-oid4vp-plugin" "keycloak-oid4vp-plugin"

# The issuer keystore is a checked-in static asset (assets/crypto/keystore.p12).

# Render the realm (reads .env: realm name, ports, status server).
# Node loads the realm tunables natively (--env-file when e2e/.env exists).
ENV_FILE_ARG=()
[ -f "$E2E_DIR/.env" ] && ENV_FILE_ARG=(--env-file="$E2E_DIR/.env")
node "${ENV_FILE_ARG[@]}" "$E2E_DIR/assets/realm/index.ts" > "$BUILD_DIR/realm.json" ||
  die "Rendering the realm failed"

log "Setup done."
