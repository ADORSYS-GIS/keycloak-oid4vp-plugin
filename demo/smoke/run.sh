#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/../_common.sh"

ensure_demo_realm
log "Running one-shot smoke flow..."
run_demo_java demo.smoke.SmokeDemo
