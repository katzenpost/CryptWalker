---
title: CryptWalker
---

{{% blocks/cover title="CryptWalker" height="med" %}}
A cryptographic library for Lean 4, where a primitive's type states what must be proved about it.

<a class="btn btn-lg btn-primary me-3 mb-4" href="/docs/overview/">Overview</a>
<a class="btn btn-lg btn-secondary me-3 mb-4" href="/api/">API reference</a>
{{% /blocks/cover %}}

{{% blocks/section color="white" %}}
<div class="col-lg-10 mx-auto">

## Abstract

CryptWalker is an experiment in using dependent types to represent cryptographic primitives.
The usual approach is to write the code first and the theorems about it later. CryptWalker
works the other way round. Each kind of primitive is a dependently typed structure that holds
the primitive's data and operations, plus one or more proposition fields that state what we
would want to prove about it. Writing an instance of the structure means discharging those
propositions. Correctness obligations are part of the interface, not an afterthought.

The non-interactive key exchange (NIKE) type shows the idea. It has a field called `commutes`
which states that the group operation is commutative: g^x^y = g^y^x. Anyone who provides a NIKE
instance, X25519 for example, has to prove `commutes` for that instance. CryptWalker contains two
X25519 implementations. The first is a constant-time Montgomery ladder ported from Rust by hand,
and proving commutativity for it directly is hard. The second is built on Mathlib's
elliptic-curve API. Mathlib already proves the group laws, so its proof takes a line or two.

## Overview

The library covers the building blocks of modern, post-quantum-ready protocols:
- **Key exchange and key encapsulation:** X25519, ML-KEM-768 (FIPS 203), a hedged ML-KEM-768
  variant, and a security-preserving KEM combiner that builds X25519 + ML-KEM-768 hybrids.
- **Signatures:** Ed25519, plain and blinded.
- **Authenticated encryption:** AES-256-GCM-SIV.
- **Hashing:** SHA-2, BLAKE2b and its XOF.
- **Key derivation:** HKDF and Argon2.
- **Stream ciphers and wide-block ciphers:** AES-CTR, ChaCha20 and AEZ.

On top of these primitives sit two protocol components. The first is the Sphinx packet format,
in both its NIKE and KEM forms, with any number of hops. The second is BACAP (Blinded
Cryptographic Capabilities), a building block for private messaging systems.

Interoperability is checked byte for byte. The test suites run known-answer vectors from NIST
ACVP and the relevant RFCs, plus vectors from the Go implementations in
[hpqc](https://github.com/katzenpost/hpqc) and [Katzenpost](https://github.com/katzenpost/katzenpost),
which are copied into the repository. CryptWalker's Sphinx packets are binary compatible with
the Katzenpost mixnet's Sphinx implementation, including when the per-hop KEM is the
post-quantum hybrid.

CryptWalker is written partly by people and partly by LLM agents. Vector-based tests are how we
keep that code honest: no primitive counts as implemented until it reproduces the reference
outputs exactly. The library is free software under the AGPLv3. Its API reference is generated
directly from the Lean sources.

</div>
{{% /blocks/section %}}
