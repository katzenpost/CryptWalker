/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import LatticeCrypto.MLKEM.Primitives
import LatticeCrypto.MLKEM.Concrete.NTT
import LatticeCrypto.MLKEM.Concrete.Encoding
import LatticeCrypto.MLKEM.Concrete.CBD
import HashSig.SLHDSA.Concrete.Keccak
import Cryptlib.Util.Bytes

/-! # ML-KEM primitives, for every FIPS 203 parameter set

VCVio's pure-Lean NTT, encoding and CBD, with SHA-3/SHAKE from the pure-Lean Keccak sponge in
`HashSig.SLHDSA.Concrete.Keccak` in place of VCVio's FFI hash bindings. -/

namespace Cryptlib.Primitives.KEM.FIPS203

open MLKEM
open MLKEM.Concrete
open SLHDSA.Concrete.Keccak

abbrev vectorToByteArray {n : Nat} (v : Vector UInt8 n) : ByteArray :=
  Cryptlib.Util.Bytes.ofVector v

/-- `n` bytes of `ba` from `offset`. -/
def byteArrayToVector (ba : ByteArray) (offset : Nat) (n : Nat) : Vector UInt8 n :=
  Vector.ofFn fun ⟨i, _⟩ => ba.get! (offset + i)

/-! ## SampleNTT (FIPS 203 Algorithm 7): rejection sampling from SHAKE-128 -/

def rejectionSample (stream : ByteArray) : Array Coeff := Id.run do
  let mut acc : Array Coeff := Array.mkEmpty 256
  let numChunks := stream.size / 3
  for chunk in [0:numChunks] do
    if acc.size < 256 then
      let pos := chunk * 3
      let b0 := stream.get! pos |>.toNat
      let b1 := stream.get! (pos + 1) |>.toNat
      let b2 := stream.get! (pos + 2) |>.toNat
      let d1 := b0 + 256 * (b1 % 16)
      let d2 := b1 / 16 + 16 * b2
      if d1 < modulus && acc.size < 256 then
        acc := acc.push (d1 : Coeff)
      if d2 < modulus && acc.size < 256 then
        acc := acc.push (d2 : Coeff)
  return acc

def requireFullRejectionSample (coeffs : Array Coeff) : Array Coeff :=
  if _h : coeffs.size = ringDegree then
    coeffs
  else
    panic! s!"ML-KEM rejection sampler produced {coeffs.size} coefficients; expected {ringDegree}"

def concreteSampleNTT (rho : Seed32) (j i : Nat) : Tq :=
  let input := vectorToByteArray rho |>.push j.toUInt8 |>.push i.toUInt8
  let stream := shake128 input 840
  let coeffs := requireFullRejectionSample (rejectionSample stream)
  ⟨Vector.ofFn fun ⟨idx, _⟩ => coeffs.getD idx 0⟩

/-! ## PRF + CBD (FIPS 203 Algorithms 6 + 8), and the two hash wrappers -/

/-- `PRF_η(σ, N) = SHAKE-256(σ ‖ N, 64η)` followed by `CBD_η`. -/
def prfCBD (eta : Nat) (sigma : Seed32) (n : Nat) : Rq :=
  let input := vectorToByteArray sigma |>.push n.toUInt8
  let prfOutput := shake256 input (64 * eta)
  samplePolyCBD eta prfOutput

/-- `G(input) = SHA3-512(input)`, split into two 32-byte halves. -/
def hashG (input : ByteArray) : Seed32 × Seed32 :=
  let hash := sha3_512 input
  (byteArrayToVector hash 0 32, byteArrayToVector hash 32 32)

/-- `H(input) = SHA3-256(input)` as a 32-byte vector. -/
def hashH (input : ByteArray) : Vector UInt8 32 :=
  byteArrayToVector (sha3_256 input) 0 32

/-! ## A faster `byteEncodeVec`

VCVio's `byteEncodeVec` computes each output byte by encoding that byte's whole polynomial again,
so encoding `u` re-encodes each polynomial `32·d_u` times; it was nearly all of encapsulation's
time. This version encodes each polynomial once and reads the bytes from that. -/

def byteEncodeVecFast (d : Nat) {k : Nat} (v : RqVec k) : ByteArray :=
  let encs : Vector ByteArray k := Vector.ofFn fun i => byteEncode d v[i]
  let chunkSize := 32 * d
  ByteArray.mk <| Array.ofFn fun idx : Fin (chunkSize * k) =>
    have hpoly : idx.val / chunkSize < k := Nat.div_lt_of_lt_mul idx.isLt
    ((encs[idx.val / chunkSize]'hpoly)[idx.val % chunkSize]?).getD 0

theorem byteEncodeVecFast_eq (d : Nat) {k : Nat} (v : RqVec k) :
    byteEncodeVecFast d v = byteEncodeVec d v := by
  unfold byteEncodeVecFast byteEncodeVec
  dsimp only
  apply congrArg ByteArray.mk
  apply congrArg Array.ofFn
  funext idx
  by_cases hd : d = 0
  · exfalso
    have := idx.isLt
    simp [hd] at this
  · simp only [hd, dif_neg, not_false_eq_true, Vector.getElem_ofFn]
    rfl

/-! ## `Primitives` instance per parameter set -/

def concretePrimitives (params : Params) (encoding : Encoding params)
    (hEnc : encoding.EncodedTHat = ByteArray)
    (hU : encoding.EncodedU = ByteArray)
    (hV : encoding.EncodedV = ByteArray) :
    Primitives params encoding where
  gKeygen := fun d =>
    hashG (vectorToByteArray d |>.push params.k.toUInt8)
  sampleNTT := fun rho j i =>
    concreteSampleNTT rho j.val i.val
  prfEta1 := prfCBD params.eta1
  prfEta2 := prfCBD params.eta2
  gEncaps := fun m ekHash =>
    hashG (vectorToByteArray m ++ vectorToByteArray ekHash)
  hEncapsulationKey := fun tHatEncoded rho =>
    hashH (hEnc ▸ tHatEncoded ++ vectorToByteArray rho)
  jReject := fun z uEncoded vEncoded =>
    byteArrayToVector
      (shake256 (vectorToByteArray z ++ hU ▸ uEncoded ++ hV ▸ vEncoded) 32) 0 32

section

variable (ps : ParameterSet)

/-- The FIPS 203 parameters of `ps`. -/
abbrev params : Params := ps.params

/-- VCVio's pure-Lean `Concrete.Encoding`, with `byteEncodeVecFast` for `byteEncodeDUVec`. -/
abbrev encoding : Encoding (params ps) :=
  { concreteEncoding (params ps) with byteEncodeDUVec := byteEncodeVecFast (params ps).du }

theorem encoding_eq : encoding ps = concreteEncoding (params ps) := by
  have h : byteEncodeVecFast (params ps).du = (concreteEncoding (params ps)).byteEncodeDUVec :=
    funext fun u => byteEncodeVecFast_eq _ u
  simp only [encoding, h]

/-- Encoding round-trip laws, from VCVio's via `encoding_eq`. -/
theorem encodingLaws : (encoding ps).Laws := by
  rw [encoding_eq]
  exact concreteEncodingLaws (params ps) (by cases ps <;> decide) (by cases ps <;> decide)
    (by cases ps <;> decide) (by cases ps <;> decide)

theorem encoding_byteEncodeDUVec_size (u : RqVec (params ps).k) :
    ((encoding ps).byteEncodeDUVec u : ByteArray).size = 32 * (params ps).du * (params ps).k := by
  show (byteEncodeVecFast (params ps).du u).size = _
  rw [byteEncodeVecFast_eq]
  exact byteEncodeVec_size _ u

def primitives : Primitives (params ps) (encoding ps) :=
  concretePrimitives (params ps) (encoding ps) (by rfl) (by rfl) (by rfl)


/-- The encoded types are `ByteArray`; typeclass search does not see this without these casts. -/
theorem hEncEq : (encoding ps).EncodedTHat = ByteArray := rfl
theorem hUEq : (encoding ps).EncodedU = ByteArray := rfl
theorem hVEq : (encoding ps).EncodedV = ByteArray := rfl

end

/-- VCVio's NTT ring operations. -/
abbrev ring : NTTRingOps := concreteNTTRingOps

end Cryptlib.Primitives.KEM.FIPS203
