/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Sign.Sign
import Cryptlib.Util.Combine

namespace Cryptlib.Primitives.Sign.Combiner

open Cryptlib.Primitives.Sign.Sign
open Cryptlib.Util.Combine

/-! # Combining two signature schemes

Keys and signatures are pairs, encodings concatenate, and verification is the conjunction of the
two component checks, so the hybrid is unforgeable if at least one component is.
-/

variable (s₁ s₂ : Signature)

def combineSign : Signature where
  State      := s₁.State      × s₂.State
  PublicKey  := s₁.PublicKey  × s₂.PublicKey
  PrivateKey := s₁.PrivateKey × s₂.PrivateKey
  Sig        := s₁.Sig        × s₂.Sig

  seedSize       := s₁.seedSize       + s₂.seedSize
  publicKeySize  := s₁.publicKeySize  + s₂.publicKeySize
  privateKeySize := s₁.privateKeySize + s₂.privateKeySize
  sigSize        := s₁.sigSize        + s₂.sigSize

  encodePublicKey := fun p => s₁.encodePublicKey p.1 ++ s₂.encodePublicKey p.2
  decodePublicKey := fun v => do
    let a ← s₁.decodePublicKey (splitL v)
    let b ← s₂.decodePublicKey (splitR v)
    pure (a, b)

  encodePrivateKey := fun p => s₁.encodePrivateKey p.1 ++ s₂.encodePrivateKey p.2
  decodePrivateKey := fun v => do
    let a ← s₁.decodePrivateKey (splitL v)
    let b ← s₂.decodePrivateKey (splitR v)
    pure (a, b)

  encodeSig := fun p => s₁.encodeSig p.1 ++ s₂.encodeSig p.2
  decodeSig := fun v => do
    let a ← s₁.decodeSig (splitL v)
    let b ← s₂.decodeSig (splitR v)
    pure (a, b)

  -- Split the seed so each component gets independent entropy.
  privateKeyFromSeed := fun v =>
    (s₁.privateKeyFromSeed (splitL v), s₂.privateKeyFromSeed (splitR v))

  pub := fun sk => (s₁.pub sk.1, s₂.pub sk.2)

  sign := fun sk m => do
    let a ← sliftL (s₁.sign sk.1 m)
    let b ← sliftR (s₂.sign sk.2 m)
    pure (a, b)

  -- Both halves must verify.
  verify := fun pk m sig => s₁.verify pk.1 m sig.1 && s₂.verify pk.2 m sig.2

  decode_encode_pub := by
    intro p
    simp [splitL_append, splitR_append, s₁.decode_encode_pub, s₂.decode_encode_pub]

  decode_encode_priv := by
    intro p
    simp [splitL_append, splitR_append, s₁.decode_encode_priv, s₂.decode_encode_priv]

  decode_encode_sig := by
    intro p
    simp [splitL_append, splitR_append, s₁.decode_encode_sig, s₂.decode_encode_sig]

  verify_sign := by
    intro sk m s
    simp only [bind, StateT.bind, sliftL, sliftR, pure, StateT.pure,
               s₁.verify_sign, s₂.verify_sign, Bool.and_self]

end Cryptlib.Primitives.Sign.Combiner
