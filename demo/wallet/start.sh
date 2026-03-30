#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/../_common.sh"

log "Starting interactive wallet CLI..."
run_demo_java demo.wallet.WalletCli
