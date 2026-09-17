/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import LatticeCrypto.MLKEM.Primitives
import LatticeCrypto.MLKEM.Concrete.NTT
import LatticeCrypto.MLKEM.Concrete.Encoding
import LatticeCrypto.MLKEM.Concrete.CBD
import HashSig.SLHDSA.Concrete.Keccak
import CryptWalker.Util.Bytes

/-! # ML-KEM-768: pure-Lean, FFI-free primitives

VCVio (a dependency of this project, mainly for `Sphinx.Indistinguishability`/`Integrity`'s
oracle-computation framework) carries a full FIPS 203 ML-KEM formalization under
`LatticeCrypto.MLKEM`. Its arithmetic core — `Concrete.NTT`/`Concrete.Encoding`/`Concrete.CBD` —
is pure, executable Lean with no native dependency, and is reused here unchanged. Its own concrete
`Primitives` bundle (`Extern.MLKEM.Instance.concretePrimitives`) is not: it calls SHA-3/SHAKE via
`Extern.MLKEM.FFI`'s `@[extern]` bindings into `mlkem-native`, a git submodule that isn't checked
out in this project's tree (confirmed: `third_party/mlkem-native` is empty), so those bindings
would build as empty stub archives — unusable, not just slow.

This file re-assembles the exact same wiring `Extern.MLKEM.Instance.lean` does, substituting
`HashSig.SLHDSA.Concrete.Keccak`'s pure-Lean Keccak-f[1600] sponge (written for SLH-DSA, but a
peer library's plain SHA-3/SHAKE implementation, not SLH-DSA-specific code) for the FFI calls —
same function shapes, same domain-separation bytes (`0x06` for SHA-3, `0x1f` for SHAKE), so this
is a drop-in substitution, not a reimplementation of the hashing itself.

Deliberately *not* reusing `LatticeCrypto.MLKEM.KEM`'s or `LatticeCrypto.MLKEM.Internal`'s
top-level `keygen`/`encaps`/`decaps` — see `MLKEM768.lean`, which writes those directly against
this file's primitives instead, keeping that thin hash-composition layer (where FIPS 203 differs
from round-3 Kyber's extra `m ← H(m)` pre-hash) ours to vary later. -/

namespace CryptWalker.KEM.MLKEM768

open MLKEM
open MLKEM.Concrete
open SLHDSA.Concrete.Keccak

/-- As `Extern.MLKEM.Instance.vectorToByteArray` — `CryptWalker.Util.Bytes.ofVector` already does
exactly this. -/
abbrev vectorToByteArray {n : Nat} (v : Vector UInt8 n) : ByteArray :=
  CryptWalker.Util.Bytes.ofVector v

/-- As `Extern.MLKEM.Instance.byteArrayToVector`, verbatim (kept as its own definition rather
than routed through `CryptWalker.Util.Bytes.toVecN`, to stay byte-for-byte identical to the
upstream helper this whole file otherwise mirrors). -/
def byteArrayToVector (ba : ByteArray) (offset : Nat) (n : Nat) : Vector UInt8 n :=
  Vector.ofFn fun ⟨i, _⟩ => ba.get! (offset + i)

/-! ## SampleNTT (FIPS 203 Algorithm 7) — rejection sampling from SHAKE-128

As `Extern.MLKEM.Instance.{rejectionSample,requireFullRejectionSample,concreteSampleNTT}`,
verbatim except `FFI.shake128` → `Keccak.shake128`. -/

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

/-! ## Concrete `Primitives` instance, and the assembled ML-KEM-768 bundle -/

/-- As `Extern.MLKEM.Instance.concretePrimitives`, verbatim except every FFI hash call routed
through `Keccak` instead. -/
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

/-- ML-KEM-768's fixed parameters (`k=3, eta1=2, eta2=2, du=10, dv=4`, matching FIPS 203). -/
abbrev params : Params := mlkem768

/-- Concrete encoding for ML-KEM-768 — reused unchanged from VCVio's pure-Lean
`Concrete.Encoding`. -/
abbrev encoding : Encoding params := concreteEncoding params

/-- Encoding round-trip laws for ML-KEM-768 — reused unchanged from VCVio. -/
theorem encodingLaws : encoding.Laws :=
  concreteEncodingLaws params (by decide) (by decide) (by decide) (by decide)

/-- The assembled, pure-Lean primitives bundle for ML-KEM-768. -/
def primitives : Primitives params encoding :=
  concretePrimitives params encoding (by rfl) (by rfl) (by rfl)

/-- The NTT ring operations ML-KEM-768 uses — reused unchanged from VCVio's pure-Lean
`Concrete.NTT`. -/
abbrev ring : NTTRingOps := concreteNTTRingOps

end CryptWalker.KEM.MLKEM768
