#!/usr/bin/env bash
# Fail if any theorem in the given Lean files depends on an axiom beyond Lean's own
# (propext, Classical.choice, Quot.sound): no sorry, no native_decide, no declared axiom.
#
# Usage: scripts/check-axioms.sh [FILE...]   (default: CryptWalker/GroupChat/*.lean)
set -euo pipefail
cd "$(dirname "$0")/.."
files=("$@")
[ ${#files[@]} -eq 0 ] && files=(CryptWalker/GroupChat/*.lean)
tmp=$(mktemp --suffix=.lean)
trap 'rm -f "$tmp"' EXIT
for f in "${files[@]}"; do
  mod=$(sed -e 's|/|.|g' -e 's|\.lean$||' <<<"$f")
  ns=$(sed -n 's/^namespace \(.*\)/\1/p' "$f" | head -1)
  names=$(sed -n 's/^theorem \([^ ]*\).*/\1/p' "$f")
  [ -z "$names" ] && continue
  echo "import $mod" >>"$tmp.head"
  for n in $names; do echo "#print axioms $ns.$n" >>"$tmp.body"; done
done
cat "$tmp.head" "$tmp.body" >"$tmp"; rm -f "$tmp.head" "$tmp.body"
out=$(lake env lean "$tmp" 2>&1)
echo "$out"
if grep -v "depends on axioms: \[\(propext\|Classical.choice\|Quot.sound\)\(, \(propext\|Classical.choice\|Quot.sound\)\)*\]$\|does not depend on any axioms" <<<"$out" | grep -q .; then
  echo "FAIL: a theorem depends on something beyond Lean's own axioms" >&2
  exit 1
fi
echo "every theorem depends on Lean's own axioms only"
