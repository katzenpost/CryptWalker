/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM768Primitives
import LatticeCrypto.MLKEM.Internal

/-! # ML-KEM-768: fixed-width wire types

VCVio's `EncapsulationKey`/`DecapsulationKey`/`Ciphertext` (all aliases into `KPKE`'s structures)
carry their serialized polynomial data as `encoding.EncodedTHat`/`EncodedU`/`EncodedV` — literally
`ByteArray` for the concrete encoding (`MLKEM768Primitives.hEncEq`/`hUEq`/`hVEq`), but not
*syntactically* so: typeclass search (e.g. resolving `++`) won't unfold `encoding`'s definition to
discover this on its own, so every place below that needs to treat one of these fields as a plain
`ByteArray` casts through the relevant equality explicitly via `cast` (`tBytes`/`uBytes`/`vBytes`
below and their inverses) — exactly how `Extern.MLKEM.Instance.concretePrimitives` itself handles
the same three types.

`CryptWalker.KEM.KEM` needs `Vector UInt8 publicKeySize` etc., so this file additionally wraps
each VCVio type in a subtype carrying the one fact a bare `ByteArray` field doesn't: that its size
is exactly what `byteEncode12Vec`/`byteEncodeDUVec`/`byteEncodeDV` (the only things that ever
produce one) always give it — needed because `decode ∘ encode = id` only holds for the
well-formed values `keygen768`/`encaps768` (next file) actually produce, not for an arbitrary term
of the bare, unconstrained type.

Each `decode*` function is split into a plain value-computing `decode*Val` (no subtype, no
attached proof) plus a separate `decode*Val_wf` well-formedness theorem, combined only in
`decode*`'s own one-line body. This split matters, not just for tidiness: proving
`decode ∘ encode = id` by unfolding both sides *while* the goal is still wrapped in
`Option`/`Subtype` (i.e. `rw`ing directly on a `some ⟨value, proof⟩ = some ⟨value', proof'⟩` goal)
triggers a `maxRecDepth` blowup here — the dependent proof component makes Lean's rewriter/congruence
machinery expensive on these terms. Splitting means `decode*Val (encode* x) = x.val` is provable by
plain `ByteArray`-level rewriting (no dependent proof in sight), and the final
`congrArg some (Subtype.ext ·)` step only ever needs to check definitional equality, not rewrite
under a dependent binder.

Every multi-piece encoding here is a *right-nested* concatenation (`a ++ (b ++ (c ++ ...))`) and
every decode peels pieces off the front one at a time via `extract_append_left`/`extract_append_right`,
each proved as its own named fact (`peelN`/`restN`) with an *explicit* left-hand side — avoiding
`rw`'s "rewrite every occurrence" behavior from conflating two different pieces that happen to
share the same numeric width (e.g. two `384 * k`-sized polynomials in the same secret key). -/

namespace CryptWalker.KEM.MLKEM768

open MLKEM
open CryptWalker.Util.Bytes (ofVector toVecN size_ofVector toVecN_ofVector ofVector_toVecN
  extract_append_left extract_append_right)

/-- `x : encoding.EncodedTHat`, as a plain `ByteArray`. -/
def tBytes (x : encoding.EncodedTHat) : ByteArray := cast hEncEq x

/-- The reverse of `tBytes`. -/
def bytesT (x : ByteArray) : encoding.EncodedTHat := cast hEncEq.symm x

theorem tBytes_bytesT (x : ByteArray) : tBytes (bytesT x) = x := rfl
theorem bytesT_tBytes (x : encoding.EncodedTHat) : bytesT (tBytes x) = x := rfl

/-- `x : encoding.EncodedU`, as a plain `ByteArray`. -/
def uBytes (x : encoding.EncodedU) : ByteArray := cast hUEq x

def bytesU (x : ByteArray) : encoding.EncodedU := cast hUEq.symm x

theorem uBytes_bytesU (x : ByteArray) : uBytes (bytesU x) = x := rfl
theorem bytesU_uBytes (x : encoding.EncodedU) : bytesU (uBytes x) = x := rfl

/-- `x : encoding.EncodedV`, as a plain `ByteArray`. -/
def vBytes (x : encoding.EncodedV) : ByteArray := cast hVEq x

def bytesV (x : ByteArray) : encoding.EncodedV := cast hVEq.symm x

theorem vBytes_bytesV (x : ByteArray) : vBytes (bytesV x) = x := rfl
theorem bytesV_vBytes (x : encoding.EncodedV) : bytesV (vBytes x) = x := rfl

/-- A well-formed ML-KEM-768 encapsulation key: `tHatEncoded` is exactly `384 * k = 1152` bytes,
matching what `byteEncode12Vec` (the only thing that ever produces one) guarantees. -/
abbrev PublicKey : Type :=
  {ek : EncapsulationKey params encoding // (tBytes ek.tHatEncoded).size = 384 * params.k}

/-- A well-formed decapsulation key: both 12-bit-packed polynomial vectors it carries
(`dkPKE`'s and its bundled `ekPKE`'s) are exactly `384 * k` bytes. -/
abbrev PrivateKey : Type := {dk : DecapsulationKey params encoding //
  (tBytes dk.dkPKE.sHatEncoded).size = 384 * params.k ∧
    (tBytes dk.ekPKE.tHatEncoded).size = 384 * params.k}

/-- A well-formed ciphertext: `uEncoded`/`vEncoded` are exactly `32 * du * k`/`32 * dv` bytes,
matching `byteEncodeDUVec`/`byteEncodeDV`. -/
abbrev CT : Type := {c : Ciphertext params encoding //
  (uBytes c.uEncoded).size = 32 * params.du * params.k ∧ (vBytes c.vEncoded).size = 32 * params.dv}

/-! ## `PublicKey` -/

def encodePublicKey (pk : PublicKey) : Vector UInt8 params.publicKeyBytes :=
  toVecN _ (tBytes pk.1.tHatEncoded ++ ofVector pk.1.rho)

private def decodePublicKeyVal (v : Vector UInt8 params.publicKeyBytes) :
    EncapsulationKey params encoding :=
  let b := ofVector v
  let a := b.extract 0 (384 * params.k)
  let rest := b.extract (384 * params.k) b.size
  { tHatEncoded := bytesT a, rho := toVecN 32 rest }

private theorem decodePublicKeyVal_wf (v : Vector UInt8 params.publicKeyBytes) :
    (tBytes (decodePublicKeyVal v).tHatEncoded).size = 384 * params.k := by
  show (tBytes (bytesT ((ofVector v).extract 0 (384 * params.k)))).size = 384 * params.k
  rw [tBytes_bytesT, ByteArray.size_extract]
  have hb : (ofVector v).size = 384 * params.k + 32 := size_ofVector v
  omega

def decodePublicKey (v : Vector UInt8 params.publicKeyBytes) : Option PublicKey :=
  some ⟨decodePublicKeyVal v, decodePublicKeyVal_wf v⟩

theorem decode_encode_pub (pk : PublicKey) : decodePublicKey (encodePublicKey pk) = some pk := by
  apply congrArg some
  apply Subtype.ext
  show decodePublicKeyVal (encodePublicKey pk) = pk.val
  obtain ⟨ek, hek⟩ := pk
  obtain ⟨tHatEncoded, rho⟩ := ek
  unfold decodePublicKeyVal encodePublicKey
  dsimp only
  have hsize : (tBytes tHatEncoded ++ ofVector rho).size = params.publicKeyBytes := by
    show (tBytes tHatEncoded ++ ofVector rho).size = 384 * params.k + 32
    rw [ByteArray.size_append, hek, size_ofVector]
  rw [ofVector_toVecN _ hsize]
  rw [show 384 * params.k = (tBytes tHatEncoded).size from hek.symm, extract_append_left]
  have hrest : (tBytes tHatEncoded ++ ofVector rho).extract (tBytes tHatEncoded).size
      (tBytes tHatEncoded ++ ofVector rho).size = ofVector rho := by
    have h := extract_append_right (tBytes tHatEncoded) (ofVector rho)
    rw [← ByteArray.size_append] at h
    exact h
  rw [hrest, toVecN_ofVector, bytesT_tBytes]

/-! ## `PrivateKey` -/

def encodePrivateKey (sk : PrivateKey) : Vector UInt8 params.secretKeyBytes :=
  toVecN _ (tBytes sk.1.dkPKE.sHatEncoded ++
    (tBytes sk.1.ekPKE.tHatEncoded ++ (ofVector sk.1.ekPKE.rho ++
      (ofVector sk.1.ekHash ++ ofVector sk.1.z))))

private def decodePrivateKeyVal (v : Vector UInt8 params.secretKeyBytes) :
    DecapsulationKey params encoding :=
  let b0 := ofVector v
  let sHatEncoded := b0.extract 0 (384 * params.k)
  let b1 := b0.extract (384 * params.k) b0.size
  let tHatEncoded := b1.extract 0 (384 * params.k)
  let b2 := b1.extract (384 * params.k) b1.size
  let rho := toVecN 32 (b2.extract 0 32)
  let b3 := b2.extract 32 b2.size
  let ekHash := toVecN 32 (b3.extract 0 32)
  let b4 := b3.extract 32 b3.size
  let z := toVecN 32 (b4.extract 0 32)
  { dkPKE := { sHatEncoded := bytesT sHatEncoded }
    ekPKE := { tHatEncoded := bytesT tHatEncoded, rho }, ekHash, z }

private theorem decodePrivateKeyVal_wf (v : Vector UInt8 params.secretKeyBytes) :
    (tBytes (decodePrivateKeyVal v).dkPKE.sHatEncoded).size = 384 * params.k ∧
    (tBytes (decodePrivateKeyVal v).ekPKE.tHatEncoded).size = 384 * params.k := by
  unfold decodePrivateKeyVal
  dsimp only
  rw [tBytes_bytesT, tBytes_bytesT, ByteArray.size_extract, ByteArray.size_extract]
  have hb0 : (ofVector v).size = 384 * params.k + (384 * params.k + (32 + (32 + 32))) :=
    size_ofVector v
  have hb1 : ((ofVector v).extract (384 * params.k) (ofVector v).size).size
      = (ofVector v).size - 384 * params.k := by
    rw [ByteArray.size_extract]; omega
  omega

def decodePrivateKey (v : Vector UInt8 params.secretKeyBytes) : Option PrivateKey :=
  some ⟨decodePrivateKeyVal v, decodePrivateKeyVal_wf v⟩

theorem decode_encode_priv (sk : PrivateKey) :
    decodePrivateKey (encodePrivateKey sk) = some sk := by
  apply congrArg some
  apply Subtype.ext
  show decodePrivateKeyVal (encodePrivateKey sk) = sk.val
  obtain ⟨dk, hdkPKE, hekPKE⟩ := sk
  obtain ⟨⟨sHatEncoded⟩, ⟨tHatEncoded, rho⟩, ekHash, z⟩ := dk
  simp only at hdkPKE hekPKE
  unfold decodePrivateKeyVal encodePrivateKey
  dsimp only
  -- Fully opaque abbreviations for the five pieces — never letting `rw`/defeq-checking peek back
  -- through `tBytes`/`ofVector` into `sHatEncoded`/`rho`/etc. is what keeps the peeling below cheap.
  generalize ha1def : tBytes sHatEncoded = a1 at *
  generalize ha2def : tBytes tHatEncoded = a2 at *
  generalize ha3def : ofVector rho = a3 at *
  generalize ha4def : ofVector ekHash = a4 at *
  generalize ha5def : ofVector z = a5 at *
  have h1 : a1.size = 384 * params.k := hdkPKE
  have h2 : a2.size = 384 * params.k := hekPKE
  have h3 : a3.size = 32 := ha3def ▸ size_ofVector rho
  have h4 : a4.size = 32 := ha4def ▸ size_ofVector ekHash
  have h5 : a5.size = 32 := ha5def ▸ size_ofVector z
  have hsize : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).size =
      384 * params.k + (384 * params.k + (32 + (32 + 32))) := by
    simp only [ByteArray.size_append, h1, h2, h3, h4, h5]
  rw [show params.secretKeyBytes = 384 * params.k + (384 * params.k + (32 + (32 + 32))) from rfl]
  rw [ofVector_toVecN _ hsize]
  have peel1 : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).extract 0 (384 * params.k) = a1 := by
    rw [← h1]; exact extract_append_left _ _
  have rest1 : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).extract (384 * params.k)
      (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).size = a2 ++ (a3 ++ (a4 ++ a5)) := by
    have h := extract_append_right a1 (a2 ++ (a3 ++ (a4 ++ a5)))
    rw [← ByteArray.size_append, h1] at h
    exact h
  rw [peel1, rest1]
  have peel2 : (a2 ++ (a3 ++ (a4 ++ a5))).extract 0 (384 * params.k) = a2 := by
    rw [← h2]; exact extract_append_left _ _
  have rest2 : (a2 ++ (a3 ++ (a4 ++ a5))).extract (384 * params.k) (a2 ++ (a3 ++ (a4 ++ a5))).size
      = a3 ++ (a4 ++ a5) := by
    have h := extract_append_right a2 (a3 ++ (a4 ++ a5))
    rw [← ByteArray.size_append, h2] at h
    exact h
  rw [peel2, rest2]
  have peel3 : (a3 ++ (a4 ++ a5)).extract 0 32 = a3 := by
    rw [← h3]; exact extract_append_left _ _
  have rest3 : (a3 ++ (a4 ++ a5)).extract 32 (a3 ++ (a4 ++ a5)).size = a4 ++ a5 := by
    have h := extract_append_right a3 (a4 ++ a5)
    rw [← ByteArray.size_append, h3] at h
    exact h
  rw [peel3, rest3]
  have peel4 : (a4 ++ a5).extract 0 32 = a4 := by
    rw [← h4]; exact extract_append_left _ _
  have rest4 : (a4 ++ a5).extract 32 (a4 ++ a5).size = a5 := by
    have h := extract_append_right a4 a5
    rw [← ByteArray.size_append, h4] at h
    exact h
  have a5self : a5.extract 0 32 = a5 := by rw [← h5]; exact ByteArray.extract_zero_size
  rw [peel4, rest4, a5self]
  rw [← ha1def, ← ha2def, ← ha3def, ← ha4def, ← ha5def, bytesT_tBytes, bytesT_tBytes,
    toVecN_ofVector, toVecN_ofVector, toVecN_ofVector]

/-! ## `CT` (ciphertext) -/

def encodeCiphertext (c : CT) : Vector UInt8 params.ciphertextBytes :=
  toVecN _ (uBytes c.1.uEncoded ++ vBytes c.1.vEncoded)

private def decodeCiphertextVal (v : Vector UInt8 params.ciphertextBytes) :
    Ciphertext params encoding :=
  let b := ofVector v
  let u := b.extract 0 (32 * params.du * params.k)
  let rest := b.extract (32 * params.du * params.k) b.size
  { uEncoded := bytesU u, vEncoded := bytesV rest }

private theorem decodeCiphertextVal_wf (v : Vector UInt8 params.ciphertextBytes) :
    (uBytes (decodeCiphertextVal v).uEncoded).size = 32 * params.du * params.k ∧
    (vBytes (decodeCiphertextVal v).vEncoded).size = 32 * params.dv := by
  unfold decodeCiphertextVal
  dsimp only
  rw [uBytes_bytesU, vBytes_bytesV, ByteArray.size_extract, ByteArray.size_extract]
  have hb : (ofVector v).size = 32 * params.du * params.k + 32 * params.dv := size_ofVector v
  omega

def decodeCiphertext (v : Vector UInt8 params.ciphertextBytes) : Option CT :=
  some ⟨decodeCiphertextVal v, decodeCiphertextVal_wf v⟩

theorem decode_encode_ct (c : CT) : decodeCiphertext (encodeCiphertext c) = some c := by
  apply congrArg some
  apply Subtype.ext
  show decodeCiphertextVal (encodeCiphertext c) = c.val
  obtain ⟨ct, hu, hv⟩ := c
  obtain ⟨uEncoded, vEncoded⟩ := ct
  simp only at hu hv
  unfold decodeCiphertextVal encodeCiphertext
  dsimp only
  have hsize : (uBytes uEncoded ++ vBytes vEncoded).size = params.ciphertextBytes := by
    show (uBytes uEncoded ++ vBytes vEncoded).size = 32 * params.du * params.k + 32 * params.dv
    rw [ByteArray.size_append, hu, hv]
  rw [ofVector_toVecN _ hsize]
  rw [show 32 * params.du * params.k = (uBytes uEncoded).size from hu.symm, extract_append_left]
  have hrest : (uBytes uEncoded ++ vBytes vEncoded).extract (uBytes uEncoded).size
      (uBytes uEncoded ++ vBytes vEncoded).size = vBytes vEncoded := by
    have h := extract_append_right (uBytes uEncoded) (vBytes vEncoded)
    rw [← ByteArray.size_append] at h
    exact h
  rw [hrest, bytesU_uBytes, bytesV_vBytes]

end CryptWalker.KEM.MLKEM768
