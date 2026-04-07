#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/../_common.sh"

cleanup() {
  log "Stopping demo stack..."
  compose down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

ensure_demo_realm
log "Starting interactive app CLI..."
run_demo_java demo.app.AppCli
