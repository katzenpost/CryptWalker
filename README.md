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

* X25519, adapted to KEM via hashed ElGamal (NIKE-to-KEM adapter, `sha256-v1` PRF)
* A security-preserving KEM combiner (Giacon–Heuer–Poettering split-PRF, BLAKE2b-256 keyed)

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
* BLAKE2b-512

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
* SHA256 (`sha256-v1`)

| DATAstructures |
|:---:|
* Binary Merkle Hash Tree polymorphic over the hash function


## cryptographic protocol components

* The Sphinx cryptographic packet format: KEM Sphinx and NIKE Sphinx, configurable to any number of hops, any KEM or NIKE, any payload size. Binary compatible with the Katzenpost mixnet's golang Sphinx implementation.

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
lake exe CryptWalker.Sphinx.Crypto.test      # Sphinx Hash/MAC/Stream/KDF/ChaCha20 vectors from katzenpost
lake exe CryptWalker.Sphinx.Crypto.aez_test  # AEZ v5 (Sphinx's SPRP) vectors from katzenpost
lake exe CryptWalker.Sphinx.commands_test    # Sphinx routing-command wire-format vectors from katzenpost
lake exe CryptWalker.Sphinx.nike_selftest    # NIKE-Sphinx round-trip self-tests
lake exe CryptWalker.Sphinx.kem_selftest     # KEM-Sphinx round-trip self-tests
lake exe CryptWalker.Sphinx.nike_vectors_test  # NIKE-Sphinx full-packet vectors from katzenpost
lake exe CryptWalker.Sphinx.kem_vectors_test   # KEM-Sphinx full-packet vectors from katzenpost
```

### test vector files

These JSON files in `CryptWalker/testdata/` are vendored from hpqc's
`hpqc/testvectors/cmd/generate` or katzenpost's
`katzenpost/core/sphinx/testvectors/cmd/generate`, and are binary-compatible with the
corresponding upstream test vectors:

| File | Primitive | Source |
|------|-----------|--------|
| `sha512.json` | SHA-512 | Go's `crypto/sha512` |
| `hkdf_blake2b.json` | HKDF-BLAKE2b-512 (RFC 5869) | `hpqc/bacap/testdata/hkdf_blake2b.json` |
| `aes_gcm_siv.json` | AES-256-GCM-SIV (RFC 8452) | `hpqc/bacap/testdata/aes_gcm_siv.json` |
| `blinded_ed25519.json` | Blinded Ed25519 signatures | `hpqc/sign/ed25519/testdata/blinded_ed25519.json` |
| `adapter_test_vectors.json` | NIKE-to-KEM adapter | `hpqc/kem/adapter/adapter_vectors_test.go` |
| `sphinx_hash_sha512_256.json` | SHA-512/256 (Sphinx's replay-tag hash) | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_mac_hmac_sha256.json` | HMAC-SHA256 (Sphinx's header MAC) | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_stream_aes256ctr.json` | AES-256-CTR (Sphinx's header stream cipher) | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_kdf.json` | HKDF-SHA256 (Sphinx's `PacketKeys` derivation) | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_chacha20_deterministic_rand.json` | ChaCha20 deterministic RNG | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_sprp_aez.json` | AEZ v5 (Sphinx's SPRP) | `katzenpost/core/sphinx/testvectors/cmd/generate` |
| `sphinx_commands_vectors.json` | Sphinx routing-command wire format | `katzenpost/core/sphinx/commands/testdata/sphinx_commands_vectors.json` |
| `sphinx_nike_vectors.json` | NIKE-Sphinx full packets (10: every hop count × `withSURB`) | `katzenpost/core/sphinx/testdata/sphinx_vectors.json` |
| `sphinx_kem_vectors.json` | KEM-Sphinx full packets (10: every hop count × `withSURB`) | `katzenpost/core/sphinx/testdata/kemsphinx_vectors.json` |

Two more files in that directory aren't vendored input — they're output, written by this
repo's own `gen_nike_vectors`/`gen_kem_vectors` (Lean-built packets, for katzenpost's own
`Unwrap` to check against): `lean_nike_vectors.json`, `lean_kem_vectors.json`.

## benchmarks: how to run the benchmark tests

```bash
lake exe CryptWalker.NIKE.benchmark
```

Times both X25519 implementations (Montgomery ladder and group) over the same random keys, so
they're directly comparable to each other. No numbers here — they depend entirely on the
machine it's run on.

## licensing

AGPLv3
