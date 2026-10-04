#!/usr/bin/env bash
# Run TLC on one config: ./run.sh protocol/MC_Backfill_Proposed.cfg [Module]
# The module defaults to MC_<Name>.tla when it exists, else <Name>.tla, for MC_<Name>_<x>.cfg.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
JAVA=${JAVA:-java}
JAR=$(realpath "${TLA2TOOLS:-$here/tla2tools.jar}")
dir=$(cd "$(dirname "$1")" && pwd)
cfg=$(basename "$1")
cd "$dir"
module=${2:-$(echo "$cfg" | sed -E "s/^(MC_[A-Za-z]+)_.*/\1/")}
[ -f "$module.tla" ] || module=${module#MC_}
exec "$JAVA" -XX:+UseParallelGC -DTLA-Library="$here/protocol:$here/impl" -cp "$JAR" tlc2.TLC \
    -workers auto -deadlock -cleanup \
    -metadir "${TLC_METADIR:-${TMPDIR:-/tmp}}/tlc-$$" -config "$cfg" "$module.tla"
