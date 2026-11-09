#!/usr/bin/env bash
# Wipe the generated artifacts of the suite (build/, playwright-report/, test-results/).
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf "$E2E_DIR/build" "$E2E_DIR/playwright-report" "$E2E_DIR/test-results"
