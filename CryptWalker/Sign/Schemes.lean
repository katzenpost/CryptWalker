/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign
import CryptWalker.Sign.Blindable
import CryptWalker.Sign.Combiner
import CryptWalker.Sign.Convert

namespace CryptWalker.Sign.Schemes

open CryptWalker.Sign.Sign
open CryptWalker.Sign.Blindable

/-! # Ed25519 with key blinding, axiomatized

CryptWalker has no Ed25519 yet — no Edwards curve arithmetic, no SHA-512. This module supplies
a `Blindable` instance whose *operations* and *laws* are named axioms, so that the abstractions
in this directory are demonstrably inhabitable and the derived theorems about them are not
vacuous. Nothing here executes.

The types are real, not axiomatized: an Ed25519 public key is a 32-byte compressed Edwards
point, a private key is a 32-byte little-endian scalar in `Z_ℓ`, and a signature is
`R ‖ s`, 64 bytes. Only the functions on them are assumed.

Why `axiom` rather than `opaque`: an `opaque` constant has no definitional unfolding and can
never be replaced by a real implementation — the mistake that made `opaque kemSpec : KEM`
un-instantiable. An `axiom` is deleted and replaced by a `def` when the implementation lands,
and until then `#print axioms` names every assumption. There are thirteen, listed below.
-/

/-- A compressed Edwards point. -/
abbrev PubBytes := Vector UInt8 32
/-- A little-endian scalar in `Z_ℓ`. Following the Echomix paper, the private key *is* the
scalar; seed expansion (`clamp(SHA-512(seed))`, `blinded25519.go:196-197`) belongs to key
generation and is not modelled here. -/
abbrev ScalarBytes := Vector UInt8 32
/-- `R ‖ s`. -/
abbrev SigBytes := Vector UInt8 64

/-! ## Assumed operations -/

/-- Seed expansion, `clamp(SHA-512(seed))` at `blinded25519.go:196-197`. This is the step the
`Blindable` abstraction deliberately leaves to key generation rather than modelling. -/
axiom scalarFromSeed : Vector UInt8 32 → ScalarBytes

/-- `sk ↦ sk · B`. `edwards25519.Point.ScalarBaseMult`. -/
axiom pubOf : ScalarBytes → PubBytes

/-- The vendored scalar-based signer at `blinded25519.go:138-189`: it operates on a bare
scalar rather than an RFC 8032 seed, deriving its nonce as
`SHA-512(d[32:64] ‖ msg ‖ d[33:64])` where `d = SHA-512(sk)`. Deterministic. -/
axiom signWith : ScalarBytes → ByteArray → SigBytes

/-- Standard RFC 8032 verification; `eddsa.go:247` uses `crypto/ed25519.Verify` unchanged,
which is why blinded signatures verify under ordinary verifiers. -/
axiom verifyWith : PubBytes → ByteArray → SigBytes → Bool

/-- `pk ↦ f · pk`, variable-base scalar multiplication. `blinded25519.go:320`. -/
axiom blindPubBytes : PubBytes → ScalarBytes → PubBytes

/-- Scalar multiplication in `Z_ℓ`. `edwards25519.Scalar.Multiply`. -/
axiom mulScalar : ScalarBytes → ScalarBytes → ScalarBytes

/-- Scalar inversion in `Z_ℓ`. `edwards25519.Scalar.Invert`, used by
`BlindedPrivateKey.Unblind` at `blinded25519.go:267`. -/
axiom invScalar : ScalarBytes → ScalarBytes

/-- Turn arbitrary bytes into a blinding factor. In Go this is
`clamp(SHA-512/256(factor))` — note the *second* hash, applied to whatever the KDF produced
(`blinded25519.go:214-216`). -/
axiom scalarOfByteArray : ByteArray → ScalarBytes

/-! ## Assumed laws -/

/-- Correctness of the vendored signer. -/
axiom verify_signWith : ∀ sk m, verifyWith (pubOf sk) m (signWith sk m) = true

/-- The blinding homomorphism: `(f · sk) · B = f · (sk · B)`. True in the Edwards group by
associativity of scalar multiplication; assumed here only because the group is not yet
formalised. Once an Ed25519 group model exists this becomes `mul_smul` and the axiom goes. -/
axiom blindPub_hom : ∀ sk f, pubOf (mulScalar f sk) = blindPubBytes (pubOf sk) f

/-- Blinding twice is blinding by the product. -/
axiom blindPub_assoc : ∀ pk f g,
  blindPubBytes (blindPubBytes pk f) g = blindPubBytes pk (mulScalar f g)

/-- `Z_ℓ` is commutative. -/
axiom mulScalar_comm : ∀ f g, mulScalar f g = mulScalar g f

/-- Unblinding inverts blinding. -/
axiom blindPub_inv : ∀ pk f, blindPubBytes (blindPubBytes pk f) (invScalar f) = pk

/-! ## The instance

All three definitions below are `noncomputable`: they are built from axioms, which have no
code. Lean enforcing that is the point — the compiler is telling us the model does not run.
When the primitives land, the axioms above become `def`s and `noncomputable` comes off. -/

/-- Ed25519 as a plain signature scheme. `State` is `Unit` because the signer is
deterministic; the state is threaded through untouched.

Encodings are the identity on the byte vectors, so `decodePublicKey` accepts every 32-byte
string. A real instance should reject non-canonical points — the counterpart of `NIKE.Safe`
for this scheme — but that check needs curve arithmetic to express. -/
noncomputable def ed25519Signature : Signature where
  State      := Unit
  PublicKey  := PubBytes
  PrivateKey := ScalarBytes
  Sig        := SigBytes

  seedSize       := 32
  publicKeySize  := 32
  privateKeySize := 32
  sigSize        := 64

  encodePublicKey  := id
  decodePublicKey  := some
  encodePrivateKey := id
  decodePrivateKey := some
  encodeSig        := id
  decodeSig        := some

  privateKeyFromSeed := scalarFromSeed
  pub    := pubOf
  sign   := fun sk m => pure (signWith sk m)
  verify := verifyWith

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_sig  := fun _ => rfl
  verify_sign        := fun sk m _ => verify_signWith sk m

/-- Ed25519 with key blinding. Note `blindPriv` is not a separate assumed operation: blinding
a private key *is* scalar multiplication, `S_i^ctx = S_R × K_i^ctx mod ℓ`, exactly as the
paper states it. -/
noncomputable def ed25519Blindable : Blindable where
  base   := ed25519Signature
  Scalar := ScalarBytes

  mul           := mulScalar
  inv           := invScalar
  scalarOfBytes := scalarOfByteArray

  blindPriv := fun sk f => mulScalar f sk
  blindPub  := blindPubBytes

  blind_hom   := blindPub_hom
  blind_assoc := blindPub_assoc
  blind_comm  := mulScalar_comm
  blind_inv   := blindPub_inv

/-- A hybrid signature: Ed25519 paired with a second scheme. Instantiated here with Ed25519
twice, since no post-quantum scheme exists in CryptWalker yet; the intended pairing is
Ed25519 + Falcon, matching hpqc's `sign/hybrid`. -/
noncomputable def ed25519Hybrid : Signature :=
  Combiner.combineSign ed25519Signature ed25519Signature

end CryptWalker.Sign.Schemes
