#!/usr/bin/env bash
# Run every MC_*.cfg and compare TLC's verdict with the EXPECT line at its top.
set -uo pipefail
cd "$(dirname "$0")"
status=0
for cfg in ${@:-MC_*.cfg}; do
    # FAST=1 (CI) skips configs marked "\* SLOW" on their second line.
    if [ "${FAST:-0}" = 1 ] && sed -n 2p "$cfg" | grep -q '^\\\* SLOW'; then
        echo "skip $cfg: slow"
        continue
    fi
    expect=$(sed -n 's/^\\\* EXPECT \(pass\|violated [A-Za-z]*\).*/\1/p' "$cfg" | head -1)
    out=$(./run.sh "$cfg" 2>&1)
    if grep -q "No error has been found" <<<"$out"; then
        got=pass
    elif v=$(grep -oE "(Invariant|Temporal property) [A-Za-z]+ is violated|Property [A-Za-z]+ is violated" <<<"$out" | head -1); [ -n "$v" ]; then
        got="violated $(awk '{print $(NF-2)}' <<<"$v")"
    else
        got="error"
    fi
    if [ "$got" = "$expect" ]; then
        echo "ok   $cfg: $got"
    else
        echo "FAIL $cfg: expected '$expect', got '$got'"
        grep -E "^Error" <<<"$out" | head -5
        status=1
    fi
done
exit $status
