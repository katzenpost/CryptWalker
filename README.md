# Crypt Walker

*A cryptographic library for Lean.*


## abstract

This library is an experiment in using dependent types for representing cryptographic primitives.
Instead of writing some cryptographic code in lean and then writing some theorems and proofs about it later,
we take a different approach; instead we write a dependently typed struture in lean, that represents that
data and the operations of the primitive with one or more proposition fields whose hypothesis is the same
as what we would want to prove about the cryptographic primitive. As an example take a look at our NIKE definition.
It's got a struct field called "commutes" we says that the group operation is commutative, g^x^y = g^y^x.
This is a proof burden to anyone writing an instance of the NIKE type, say for X25519, you need to prove
the "commutes" hypothesis for your specific type instance.

This library so far has two implementations of X25519. One of them, a
montgomery ladder implementation, I ported from rust to lean mostly by
hand. Too difficult to prove the operations commute. The other is
entirely written by an LLM agent specifically to have an easy proof.
It uses an existing lean elliptic curve API that exists in mathlib,
and therefore already has existing group lemmas that says the group
operations commute. Therefore the proof is one or two lines of code.

This library is also a mix of Lean code written by humans and by LLM agents.
We mitigate LLM slop code by means of test vector based unit tests. 
For example when implementing BACAP and Sphinx, we first ensured all the necessary test vectors
were present in the hpqc golang cryptography library, here: https://github.com/katzenpost/hpqc
Then we copied those test vectors into the CryptWalker git repo and used them in our verification
step to ensure every cryptographic primitive was implemented correctly.

TODO: we should probably include all the KAT test vectors for every cryptographic primitive implemented
in this library.


## cryptographic primitives

| NIKE: Non-Interactive Key Exchange |
|:---:|

Classical NIKEs, two independent implementations of the same exchange:
* X25519 — constant-time Montgomery ladder (RFC 7748)
* X25519 — group formulation over Mathlib's Weierstrass-curve API (commutativity is
  `Nat.mul_comm`, not an axiom, unlike the ladder's)

| KEM: Key Encapsulation Method |
|:---:|

* X25519, adapted to KEM via hashed ElGamal (NIKE-to-KEM adapter) — both `blake2b-xof`, hpqc's
  deployed PRF, and `sha256-v1`, a portable stand-in for implementations without BLAKE2b
* ML-KEM-768 (FIPS 203), built from [VCVio](https://github.com/dtumad/VCV-io)'s pure-Lean
  primitives (NTT, CBD, encoding) with our own `keygen`/`encaps`/`decaps` composition — checked
  against the official NIST ACVP known-answer vectors (keygen, encapsulation, decapsulation
  including implicit rejection, and both key-validity checks). A future variant will also hash the
  encapsulation message `m` before use, restoring a randomness-hedging step NIST dropped when
  standardizing ML-KEM from Kyber.
* A security-preserving KEM combiner (Giacon–Heuer–Poettering split-PRF, real BLAKE2b-256 keyed),
  generic over any number of ingredient KEMs — instantiated as an X25519 + ML-KEM-768 hybrid,
  cross-checked byte-for-byte against [hpqc](https://github.com/katzenpost/hpqc)'s own combiner

| SIGN: Cryptographic Signature Scheme |
|:---:|
* Ed25519 (RFC 8032), plain and blinded variants

| AEAD: Authenticated Encryption with Associated Data |
|:---:|
* AES-256-GCM-SIV (RFC 8452), the misuse-resistant mode BACAP encrypts pigeonhole boxes with,
  built on AES-256 and POLYVAL (RFC 8452 §3)

| HASH: Cryptographic Hash Function |
|:---:|
* SHA-512, and its truncated SHA-512/256 variant
* SHA-256
* BLAKE2b, parameterized over digest length and an optional key (RFC 7693's keyed mode) — used at
  512 bits unkeyed (BACAP, HKDF) and at 256 bits both unkeyed and keyed (the KEM combiner's PRF)
* BLAKE2b's XOF, BLAKE2Xb (blake2x.pdf) — the deployed NIKE-to-KEM adapter PRF

| MAC: Message Authentication Code |
|:---:|
* HMAC-SHA256 (RFC 2104), Sphinx's header MAC

| Stream ciphers |
|:---:|
* AES-256-CTR, Sphinx's header/routing-info stream cipher
* ChaCha20 (original/Bernstein construction, 64-bit nonce), Sphinx's deterministic RNG

| SPRP: wide-block cipher |
|:---:|
* AEZ v5, restricted to Sphinx's exact usage (τ=0, pure-SPRP mode) — encrypts Sphinx's payload

| KDF: Key Derivation Function |
|:---:|
* HKDF-BLAKE2b-512 (RFC 5869 with BLAKE2b-512 as the hash)
* HKDF-SHA256 (RFC 5869, Expand-only), Sphinx's `PacketKeys` derivation

| PRF: Pseuodo Random Function |
|:---:|
* BLAKE2b XOF (`blake2b-xof`)
* SHA256 (`sha256-v1`)

| DATAstructures |
|:---:|
* Binary Merkle Hash Tree polymorphic over the hash function


## cryptographic protocol components

* The Sphinx cryptographic packet format: KEM Sphinx and NIKE Sphinx, configurable to any number of hops, any KEM or NIKE, any payload size. Binary compatible with the Katzenpost mixnet's golang Sphinx implementation — including with a post-quantum/classical hybrid KEM (X25519 + ML-KEM-768) as the per-hop KEM.

* BACAP: Blinded Cryptographic Capability. It's like having a private distributed hash table. Useful for building messaging systems.


## building this software

```bash
lake build
```

## testing: how to run the unit tests

Some tests load known-answer test vectors from `CryptWalker/testdata/`, vendored from
[hpqc](https://github.com/katzenpost/hpqc) and [katzenpost](https://github.com/katzenpost/katzenpost)
to ensure binary compatibility.

```bash
make test   # build everything and run every suite, reporting all failures
make help   # list every make target, including one per suite
```

Or run any suite directly:

```bash
lake exe CryptWalker.Data.test
lake exe CryptWalker.NIKE.test
lake exe CryptWalker.KEM.test
lake exe CryptWalker.KEM.vectors        # NIKE-to-KEM adapter vectors from hpqc
lake exe CryptWalker.Hash.test          # SHA-512 vectors from hpqc
lake exe CryptWalker.Hash.hkdf_test     # HKDF-BLAKE2b raw function vectors
lake exe CryptWalker.Hash.hkdf_structured_test  # HKDF structured instance vectors
lake exe CryptWalker.Cipher.test        # AES-256-GCM-SIV vectors from hpqc
lake exe CryptWalker.Sign.test
lake exe CryptWalker.Sign.blinded_test  # blinded Ed25519 vectors from hpqc
lake exe CryptWalker.BACAP.test         # BACAP vectors from hpqc
lake exe CryptWalker.Sphinx.crypto_test      # Sphinx Hash/MAC/Stream/KDF/ChaCha20 vectors from katzenpost
lake exe CryptWalker.WideBlockCipher.test    # AEZ v5 (Sphinx's SPRP) vectors from katzenpost
lake exe CryptWalker.Sphinx.commands_test    # Sphinx routing-command wire-format vectors from katzenpost
lake exe CryptWalker.Sphinx.nike_selftest    # NIKE-Sphinx round-trip self-tests
lake exe CryptWalker.Sphinx.kem_selftest     # KEM-Sphinx round-trip self-tests
lake exe CryptWalker.Sphinx.nike_vectors_test  # NIKE-Sphinx full-packet vectors from katzenpost
lake exe CryptWalker.Sphinx.kem_vectors_test   # KEM-Sphinx full-packet vectors from katzenpost
lake exe CryptWalker.KEM.MLKEM.mlkem768_test   # ML-KEM-768 NIST ACVP known-answer vectors
lake exe CryptWalker.Hash.blake2b_256_test     # BLAKE2b-256 (unkeyed and keyed) vectors from hpqc
lake exe CryptWalker.KEM.mlkem768_x25519_combiner_test  # X25519+ML-KEM-768 hybrid vectors from hpqc
lake exe CryptWalker.Sphinx.kem_hybrid_vectors_test     # KEM-Sphinx hybrid full-packet vectors from katzenpost
```

A few suites also have their own dedicated `make` target, for running just that piece:

```bash
make test-mlkem-kat      # just the ML-KEM-768 NIST ACVP known-answer vectors
make test-hybrid-sphinx  # just the KEM-Sphinx round-trip self-test for the hybrid KEM
make test-mlkem          # both of the above, together
```

### test vector files

These JSON files in `CryptWalker/testdata/` are vendored from hpqc's or katzenpost's own
`testvectors/cmd/generate` tools, and are binary-compatible with the corresponding upstream test
vectors — the `Source` column below is each file's canonical path in its own repo (what
`scripts/verify-vectors.sh` actually compares against, not a symlink or a consuming test file):

| File | Primitive | Source |
|------|-----------|--------|
| `sha512.json` | SHA-512 | `hpqc/testvectors/primitives/sha512.json` |
| `hkdf_blake2b.json` | HKDF-BLAKE2b-512 (RFC 5869) | `hpqc/testvectors/primitives/hkdf_blake2b.json` |
| `aes_gcm_siv.json` | AES-256-GCM-SIV (RFC 8452) | `hpqc/testvectors/primitives/aes_gcm_siv.json` |
| `blinded_ed25519.json` | Blinded Ed25519 signatures | `hpqc/testvectors/primitives/blinded_ed25519.json` |
| `blake2b_256.json` | BLAKE2b-256, unkeyed and keyed (RFC 7693) | `hpqc/testvectors/primitives/blake2b_256.json` |
| `adapter_test_vectors.json` | NIKE-to-KEM adapter | `hpqc/testvectors/kem/adapter_test_vectors.json` |
| `mlkem768_x25519_combiner.json` | X25519+ML-KEM-768 hybrid combiner (both components' raw inputs and every intermediate/combined output) | `hpqc/testvectors/kem/mlkem768_x25519_combiner.json` |
| `sphinx_hash_sha512_256.json` | SHA-512/256 (Sphinx's replay-tag hash) | `katzenpost/core/sphinx/testvectors/primitives/hash_sha512_256.json` |
| `sphinx_mac_hmac_sha256.json` | HMAC-SHA256 (Sphinx's header MAC) | `katzenpost/core/sphinx/testvectors/primitives/mac_hmac_sha256.json` |
| `sphinx_stream_aes256ctr.json` | AES-256-CTR (Sphinx's header stream cipher) | `katzenpost/core/sphinx/testvectors/primitives/stream_aes256ctr.json` |
| `sphinx_kdf.json` | HKDF-SHA256 (Sphinx's `PacketKeys` derivation) | `katzenpost/core/sphinx/testvectors/primitives/kdf_sphinx.json` |
| `sphinx_chacha20_deterministic_rand.json` | ChaCha20 deterministic RNG | `katzenpost/core/sphinx/testvectors/primitives/chacha20_deterministic_rand.json` |
| `sphinx_sprp_aez.json` | AEZ v5 (Sphinx's SPRP) | `katzenpost/core/sphinx/testvectors/primitives/sprp_aez.json` |
| `sphinx_commands_vectors.json` | Sphinx routing-command wire format | `katzenpost/core/sphinx/commands/testdata/sphinx_commands_vectors.json` |
| `sphinx_nike_vectors.json` | NIKE-Sphinx full packets (10: every hop count × `withSURB`) | `katzenpost/core/sphinx/testdata/sphinx_vectors.json` |
| `sphinx_kem_vectors.json` | KEM-Sphinx full packets (10: every hop count × `withSURB`) | `katzenpost/core/sphinx/testdata/kemsphinx_vectors.json` |
| `sphinx_kem_hybrid_vectors.json` | KEM-Sphinx full packets, X25519+ML-KEM-768 hybrid (10: every hop count × `withSURB`) | `katzenpost/core/sphinx/testdata/kemsphinx_mlkem768x25519_vectors.json` |
| `mlkem768_keygen.json`, `mlkem768_encapdecap.json`, `mlkem768_keycheck.json` | ML-KEM-768 (FIPS 203) — NIST's own official ACVP known-answer vectors, not from hpqc or katzenpost | [NIST's `usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server) |

A few more files in that directory aren't vendored input — they're output, written by this
repo's own `gen_nike_vectors`/`gen_kem_vectors`/`gen_mlkem768_x25519_combiner_vectors` (Lean-built
packets and combiner vectors, for hpqc's and katzenpost's own test suites to check against):
`lean_nike_vectors.json`, `lean_kem_vectors.json`, `lean_kem_hybrid_vectors.json`,
`lean_mlkem768_x25519_combiner_vectors.json`.

### proving the vendored vectors actually match upstream

`scripts/verify-vectors.sh` (or `make verify-vectors`) `sha256sum`-compares every vendored file
above against its source copy in a sibling `hpqc`/`katzenpost` checkout, printing both hashes side
by side:

```bash
make verify-vectors                                          # expects ../hpqc, ../katzenpost
make verify-vectors HPQC_DIR=~/hpqc KATZENPOST_DIR=~/katzenpost
```

This is nothing CryptWalker-specific — it is the same check anyone can run by hand with two
`sha256sum` invocations per file; the script just automates going through the whole list and
reports a clean pass/fail.

## benchmarks: how to run the benchmark tests

```bash
lake exe CryptWalker.NIKE.benchmark
lake exe CryptWalker.Sphinx.benchmark
```

The first times both X25519 implementations (Montgomery ladder and group) on fresh random keys,
so they're directly comparable to each other. The second times Sphinx packet creation and
first-hop unwrap for every registered scheme. No numbers here — they depend entirely on the
machine it's run on.

Both are built on [LeanBench](https://github.com/alok/LeanBench), so its CLI flags go straight
after the executable, e.g. `lake exe CryptWalker.Sphinx.benchmark --tags unwrap --samples 10` or
`--format json --save baseline.json` then `--compare baseline.json`.

## licensing

AGPLv3
