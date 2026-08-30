/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Sign.Sign

/-! # Digital signature schemes

The same shape as `CryptWalker.NIKE.NIKE` and `CryptWalker.KEM.KEM`: a plain structure whose
correctness law is a *field*, so no instance can exist without discharging it.

## Supporting randomized schemes

Two separate sources of randomness, deliberately handled differently.

*Signing* randomness lives in `StateM State`. A randomized signer (Falcon, ML-DSA,
SPHINCS+) draws its nonce from the state; a deterministic one (Ed25519) threads the state
through untouched and can take `State := Unit`. What makes this safe is the shape of
`verify_sign`: it quantifies over **every** state, so the law says *whatever* randomness the
signer consumes, the result verifies. A scheme cannot satisfy it by working only for some
lucky nonce.

*Key generation* randomness is the caller's problem, exactly as in `NIKE`:
`privateKeyFromSeed` is a pure total function from a seed. This is better than a
`generate : StateM State PrivateKey` field, which would be unusable for a deterministic
signer — with `State := Unit` such a `generate` can only be a constant, and would hand back
the same key every time. That is the degenerate-seed trap the KEM's old `init` field fell
into.

## Deliberate limits

Three things this interface does not support, each a considered choice rather than an
oversight:

* **Signatures are fixed-size.** `encodeSig` lands in `Vector UInt8 sigSize`. Falcon's native
  encoding is variable-length, so it must be used in padded form — which is exactly what
  hpqc does (`falcon_padded_512`, `falcon_padded_1024`). Relaxing this would cost the
  combiner its `splitL`/`splitR` arithmetic and force length prefixes throughout.
* **`sign` is total.** That excludes *stateful* hash-based schemes such as XMSS and LMS,
  which exhaust after a bounded number of signatures and must then refuse. Everything
  katzenpost uses — Ed25519, SPHINCS+, Falcon — is stateless, so signing genuinely cannot
  fail, and saying so in the type is worth more than the generality.
* **No context string.** Ed25519ctx and ML-DSA accept a domain-separation context at signing
  time. Nothing here needs it, and adding an argument every call site must thread for a
  scheme we do not use is the speculative generality this structure is trying to avoid.

## No `DecidableEq Sig`

Signature equality is not part of what a signature scheme means. `verify` is already the
scheme's "is this right" operation and is `Bool`-valued by construction, whereas for a
randomized scheme one message has *many* valid signatures — so `σ₁ = σ₂` is neither
necessary nor sufficient for anything. Known-answer tests compare `encodeSig` output, a
`Vector` which derives `DecidableEq` for free.
-/

structure Signature where
  State      : Type
  PublicKey  : Type
  PrivateKey : Type
  Sig        : Type

  seedSize       : Nat
  publicKeySize  : Nat
  privateKeySize : Nat
  sigSize        : Nat

  encodePublicKey  : PublicKey  → Vector UInt8 publicKeySize
  decodePublicKey  : Vector UInt8 publicKeySize  → Option PublicKey
  encodePrivateKey : PrivateKey → Vector UInt8 privateKeySize
  decodePrivateKey : Vector UInt8 privateKeySize → Option PrivateKey
  encodeSig        : Sig        → Vector UInt8 sigSize
  decodeSig        : Vector UInt8 sigSize        → Option Sig

  /-- Key generation, with the entropy supplied by the caller. Total: expanding a seed into a
  private key cannot fail. -/
  privateKeyFromSeed : Vector UInt8 seedSize → PrivateKey

  /-- The public key is derived from the private key, not generated alongside it. This is why
  `verify_sign` below can be a universal law rather than a witness carried in a `Σ'` the way
  `KEM.generate` must. -/
  pub : PrivateKey → PublicKey

  /-- Total, and stateful only to carry signing randomness. -/
  sign : PrivateKey → ByteArray → StateM State Sig

  /-- A pure predicate. It is expected to reject adversarial input, which is why it returns
  `Bool` rather than living in an error monad. -/
  verify : PublicKey → ByteArray → Sig → Bool

  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_sig  : ∀ s,  decodeSig        (encodeSig        s)  = some s

  /-- Correctness, for every private key and **every signing state**. The quantification over
  `s` is what makes this meaningful for randomized schemes. Stated with a projection rather
  than an equation hypothesis, which is available precisely because `sign` is total. -/
  verify_sign : ∀ sk m s, verify (pub sk) m (sign sk m s).1 = true

/-- The trivial scheme: one key, one signature, everything verifies. Present so `Signature` is
demonstrably inhabited and downstream constructions can be smoke-tested. Completely insecure. -/
instance : Inhabited Signature := ⟨{
  State      := Unit
  PublicKey  := Unit
  PrivateKey := Unit
  Sig        := Unit

  seedSize       := 0
  publicKeySize  := 0
  privateKeySize := 0
  sigSize        := 0

  encodePublicKey  := fun _ => #v[]
  decodePublicKey  := fun _ => some ()
  encodePrivateKey := fun _ => #v[]
  decodePrivateKey := fun _ => some ()
  encodeSig        := fun _ => #v[]
  decodeSig        := fun _ => some ()

  privateKeyFromSeed := fun _ => ()
  pub                := id
  sign               := fun _ _ => pure ()
  verify             := fun _ _ _ => true

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_sig  := fun _ => rfl
  verify_sign        := fun _ _ _ => rfl
}⟩

end CryptWalker.Sign.Sign
