#!/usr/bin/env bash
# Verify that CryptWalker's vendored test-vector files are byte-identical to their source copies
# in hpqc and katzenpost, by comparing sha256sum output side by side. Nothing in this script is
# specific to CryptWalker's tooling -- it is deliberately plain enough that a human can re-run the
# same check by hand with two `sha256sum` invocations per file listed below.
#
# Usage:
#   scripts/verify-vectors.sh [HPQC_DIR] [KATZENPOST_DIR]
#
# Both default to sibling checkouts (../hpqc, ../katzenpost relative to this repo) if not given
# and not already set as environment variables (HPQC_DIR, KATZENPOST_DIR).
#
# Exits 0 if every pair matches, 1 if any file is missing or any hash differs.

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

HPQC_DIR="${1:-${HPQC_DIR:-../hpqc}}"
KATZENPOST_DIR="${2:-${KATZENPOST_DIR:-../katzenpost}}"

# Each entry: "CryptWalker path" "source repo path, relative to HPQC_DIR or KATZENPOST_DIR".
# The source path's own repo root is substituted at comparison time.
hpqc_pairs=(
  "testdata/adapter_test_vectors.json                        testvectors/kem/adapter_test_vectors.json"
  "testdata/aes_gcm_siv.json                                 testvectors/primitives/aes_gcm_siv.json"
  "testdata/blake2b_256.json                                 testvectors/primitives/blake2b_256.json"
  "testdata/blinded_ed25519.json                             testvectors/primitives/blinded_ed25519.json"
  "testdata/hkdf_blake2b.json                                testvectors/primitives/hkdf_blake2b.json"
  "testdata/sha512.json                                      testvectors/primitives/sha512.json"
  "testdata/mlkem768_x25519_combiner.json                    testvectors/kem/mlkem768_x25519_combiner.json"
  "testdata/lean_mlkem768_x25519_combiner_vectors.json       kem/combiner/testdata/lean_mlkem768_x25519_combiner_vectors.json"
)

katzenpost_pairs=(
  "testdata/sphinx_hash_sha512_256.json                      core/sphinx/testvectors/primitives/hash_sha512_256.json"
  "testdata/sphinx_mac_hmac_sha256.json                      core/sphinx/testvectors/primitives/mac_hmac_sha256.json"
  "testdata/sphinx_kdf.json                                  core/sphinx/testvectors/primitives/kdf_sphinx.json"
  "testdata/sphinx_stream_aes256ctr.json                     core/sphinx/testvectors/primitives/stream_aes256ctr.json"
  "testdata/sphinx_chacha20_deterministic_rand.json          core/sphinx/testvectors/primitives/chacha20_deterministic_rand.json"
  "testdata/sphinx_sprp_aez.json                             core/sphinx/testvectors/primitives/sprp_aez.json"
  "testdata/sphinx_commands_vectors.json                     core/sphinx/commands/testdata/sphinx_commands_vectors.json"
  "testdata/sphinx_nike_vectors.json                         core/sphinx/testdata/sphinx_vectors.json"
  "testdata/sphinx_kem_vectors.json                          core/sphinx/testdata/kemsphinx_vectors.json"
  "testdata/sphinx_kem_hybrid_vectors.json                   core/sphinx/testdata/kemsphinx_mlkem768x25519_vectors.json"
  "testdata/lean_kem_vectors.json                            core/sphinx/testdata/lean_kem_vectors.json"
  "testdata/lean_nike_vectors.json                           core/sphinx/testdata/lean_nike_vectors.json"
  "testdata/lean_kem_hybrid_vectors.json                     core/sphinx/testdata/lean_kem_hybrid_vectors.json"
)

sha256_of() {
  if [ ! -f "$1" ]; then
    echo "MISSING"
    return
  fi
  sha256sum "$1" | cut -d' ' -f1
}

check_group() {
  local label="$1" base="$2"
  shift 2
  local -n pairs="$1"
  local group_ok=1
  printf '\n== %s (%s) ==\n' "$label" "$base"
  if [ ! -d "$base" ]; then
    printf '  SKIP  %s not found -- pass its path as an argument or set the env var\n' "$base"
    return 1
  fi
  for pair in "${pairs[@]}"; do
    local cw src a b status
    cw=$(awk '{print $1}' <<<"$pair")
    src=$(awk '{print $2}' <<<"$pair")
    a=$(sha256_of "$cw")
    b=$(sha256_of "$base/$src")
    if [ "$a" = "$b" ] && [ "$a" != "MISSING" ]; then
      status="MATCH   "
    else
      status="MISMATCH"
      group_ok=0
    fi
    printf '  %s  %s\n' "$status" "$cw"
    printf '            CryptWalker: %s  %s\n' "$a" "$cw"
    printf '            %-11s: %s  %s/%s\n' "$label" "$b" "$base" "$src"
  done
  return $((1 - group_ok))
}

ok=1
check_group "hpqc" "$HPQC_DIR" hpqc_pairs || ok=0
check_group "katzenpost" "$KATZENPOST_DIR" katzenpost_pairs || ok=0

echo
if [ "$ok" -eq 1 ]; then
  echo "all vendored test vectors match their source repos"
  exit 0
else
  echo "MISMATCH: some vendored test vectors do not match their source repos (see above)"
  exit 1
fi
