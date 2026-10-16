---
title: Primitives
weight: 20
description: The cryptographic primitives and protocol components CryptWalker implements.
---

## NIKE: non-interactive key exchange

- X25519, constant-time Montgomery ladder (RFC 7748)
- X25519 over Mathlib's Weierstrass-curve API

## KEM: key encapsulation

- X25519 turned into a KEM with hashed ElGamal (the NIKE-to-KEM adapter), using either the
  `blake2b-xof` or the `sha256-v1` PRF
- ML-KEM-768 (FIPS 203), built from [VCVio](https://github.com/dtumad/VCV-io)'s pure-Lean NTT,
  CBD and encoding, checked against NIST ACVP vectors
- Hedged ML-KEM-768, which hashes the encapsulation message before use
- A KEM combiner (Giacon–Heuer–Poettering split-PRF, keyed BLAKE2b-256) over any number of
  ingredient KEMs, instantiated as X25519 + ML-KEM-768 and cross-checked against hpqc

## Signatures

- Ed25519 (RFC 8032), plain and blinded

## AEAD

- AES-256-GCM-SIV (RFC 8452)

## Hash functions and XOFs

- SHA-256, SHA-512, SHA-512/256
- BLAKE2b, keyed and unkeyed, any digest length
- BLAKE2Xb

## MAC

- HMAC-SHA256 (RFC 2104)

## Stream ciphers

- AES-256-CTR
- ChaCha20

## Wide-block cipher

- AEZ v5, restricted to the parameters Sphinx uses

## KDF

- HKDF-BLAKE2b-512, HKDF-SHA256 (RFC 5869)
- Argon2d, Argon2i, Argon2id (RFC 9106)

## Data structures

- Binary Merkle hash tree, polymorphic over the hash function

## Protocol components

- **Sphinx:** the mix network packet format, in both NIKE and KEM variants. It works with any
  number of hops, any KEM or NIKE and any payload size, and is binary compatible with Katzenpost,
  including with the X25519 + ML-KEM-768 hybrid as the per-hop KEM.
- **BACAP:** Blinded Cryptographic Capabilities, which works like a private distributed hash
  table and is used to build messaging systems.
