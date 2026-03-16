#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=demo/_common.sh
source "$SCRIPT_DIR/_common.sh"

"$SCRIPT_DIR/setup-realm.sh"
"$SCRIPT_DIR/create-test-user.sh"

log "Building demo classpath..."
CLASS_PATH_FILE="$DEMO_DIR/target/demo.classpath"

(
  cd "$ROOT_DIR"
  ./mvnw -q -DskipTests \
    -Dmdep.includeScope=provided \
    -Dmdep.outputFile="$CLASS_PATH_FILE" \
    dependency:build-classpath
)

if [[ ! -f "$CLASS_PATH_FILE" ]]; then
  die "Failed to build classpath at $CLASS_PATH_FILE"
fi

PLUGIN_CLASSES="$ROOT_DIR/target/classes"
DEMO_CLASSES="$DEMO_DIR/target/classes"
mkdir -p "$DEMO_CLASSES"

CLASSPATH="$(cat "$CLASS_PATH_FILE"):$PLUGIN_CLASSES"

log "Compiling sample-flow.java..."
javac -cp "$CLASSPATH" -d "$DEMO_CLASSES" "$DEMO_DIR/sample-flow.java"

log "Running demo flow (wallet replacement)..."
export DEMO_BASE_URL="$KC_BASE_URL"
java -cp "$DEMO_CLASSES:$CLASSPATH" SampleFlow
