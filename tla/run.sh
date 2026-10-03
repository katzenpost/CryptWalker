#!/usr/bin/env bash
# Run TLC on one config: ./run.sh MC_Backfill_Deployed.cfg
set -euo pipefail
cd "$(dirname "$0")"
JAVA=${JAVA:-java}
JAR=${TLA2TOOLS:-tla2tools.jar}
cfg=$1
module=${2:-$(echo "$cfg" | sed -E 's/^MC_([A-Za-z]+)_.*/\1/')}
exec "$JAVA" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -deadlock -cleanup \
    -metadir "${TMPDIR:-/tmp}/tlc-$$" -config "$cfg" "$module.tla"
