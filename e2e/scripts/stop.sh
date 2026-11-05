#!/usr/bin/env bash
# Tear the stack down without touching build artifacts.
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$E2E_DIR"
docker compose down -v
