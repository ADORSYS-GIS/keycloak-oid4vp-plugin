#!/usr/bin/env bash
# Tear the stack down without touching build artifacts.
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$E2E_DIR"
if [ "${E2E_KEEP_STACK:-0}" = "1" ]; then
  echo "Leaving stack up for debugging (logs: build/docker-compose.log)."
  docker compose logs > build/docker-compose.log || true
  exit 0
fi
docker compose down -v
