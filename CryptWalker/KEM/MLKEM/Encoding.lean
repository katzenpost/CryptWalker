/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.Primitives
import LatticeCrypto.MLKEM.Internal

/-! # ML-KEM: fixed-width wire types

VCVio's `EncapsulationKey`/`DecapsulationKey`/`Ciphertext` (all aliases into `KPKE`'s structures)
carry their serialized polynomial data as `encoding.EncodedTHat`/`EncodedU`/`EncodedV` — literally
`ByteArray` for the concrete encoding (`Primitives.hEncEq`/`hUEq`/`hVEq`), but not
*syntactically* so: typeclass search (e.g. resolving `++`) won't unfold `encoding`'s definition to
discover this on its own, so every place below that needs to treat one of these fields as a plain
`ByteArray` casts through the relevant equality explicitly via `cast` (`tBytes`/`uBytes`/`vBytes`
below and their inverses) — exactly how `Extern.MLKEM.Instance.concretePrimitives` itself handles
the same three types.

`CryptWalker.KEM.KEM` needs `Vector UInt8 publicKeySize` etc., so this file additionally wraps
each VCVio type in a subtype carrying the one fact a bare `ByteArray` field doesn't: that its size
is exactly what `byteEncode12Vec`/`byteEncodeDUVec`/`byteEncodeDV` (the only things that ever
produce one) always give it — needed because `decode ∘ encode = id` only holds for the
well-formed values `keygen`/`encaps` (next file) actually produce, not for an arbitrary term
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

namespace CryptWalker.KEM.FIPS203

open MLKEM
open CryptWalker.Util.Bytes (ofVector toVecN size_ofVector toVecN_ofVector ofVector_toVecN
  extract_append_left extract_append_right)

variable (ps : ParameterSet)

theorem secretKeyBytes_eq : (params ps).secretKeyBytes =
    384 * (params ps).k + (384 * (params ps).k + (32 + (32 + 32))) := by
  simp only [Params.secretKeyBytes]; omega

theorem ciphertextBytes_eq : (params ps).ciphertextBytes =
    32 * (params ps).du * (params ps).k + 32 * (params ps).dv := by
  simp only [Params.ciphertextBytes, Nat.mul_add, Nat.mul_assoc]

/-- `x : encoding.EncodedTHat`, as a plain `ByteArray`. -/
def tBytes (x : (encoding ps).EncodedTHat) : ByteArray := cast (hEncEq ps) x

/-- The reverse of `tBytes`. -/
def bytesT (x : ByteArray) : (encoding ps).EncodedTHat := cast (hEncEq ps).symm x

theorem tBytes_bytesT (x : ByteArray) : (tBytes ps) ((bytesT ps) x) = x := rfl
theorem bytesT_tBytes (x : (encoding ps).EncodedTHat) : (bytesT ps) ((tBytes ps) x) = x := rfl

/-- `x : encoding.EncodedU`, as a plain `ByteArray`. -/
def uBytes (x : (encoding ps).EncodedU) : ByteArray := cast (hUEq ps) x

def bytesU (x : ByteArray) : (encoding ps).EncodedU := cast (hUEq ps).symm x

theorem uBytes_bytesU (x : ByteArray) : (uBytes ps) ((bytesU ps) x) = x := rfl
theorem bytesU_uBytes (x : (encoding ps).EncodedU) : (bytesU ps) ((uBytes ps) x) = x := rfl

/-- `x : encoding.EncodedV`, as a plain `ByteArray`. -/
def vBytes (x : (encoding ps).EncodedV) : ByteArray := cast (hVEq ps) x

def bytesV (x : ByteArray) : (encoding ps).EncodedV := cast (hVEq ps).symm x

theorem vBytes_bytesV (x : ByteArray) : (vBytes ps) ((bytesV ps) x) = x := rfl
theorem bytesV_vBytes (x : (encoding ps).EncodedV) : (bytesV ps) ((vBytes ps) x) = x := rfl

/-- A well-formed ML-KEM encapsulation key: `tHatEncoded` is exactly `384 * k = 1152` bytes,
matching what `byteEncode12Vec` (the only thing that ever produces one) guarantees. -/
abbrev PublicKey : Type :=
  {ek : EncapsulationKey (params ps) (encoding ps) // ((tBytes ps) ek.tHatEncoded).size = 384 * (params ps).k}

/-- A well-formed decapsulation key: both 12-bit-packed polynomial vectors it carries
(`dkPKE`'s and its bundled `ekPKE`'s) are exactly `384 * k` bytes. -/
abbrev PrivateKey : Type := {dk : DecapsulationKey (params ps) (encoding ps) //
  ((tBytes ps) dk.dkPKE.sHatEncoded).size = 384 * (params ps).k ∧
    ((tBytes ps) dk.ekPKE.tHatEncoded).size = 384 * (params ps).k}

/-- A well-formed ciphertext: `uEncoded`/`vEncoded` are exactly `32 * du * k`/`32 * dv` bytes,
matching `byteEncodeDUVec`/`byteEncodeDV`. -/
abbrev CT : Type := {c : Ciphertext (params ps) (encoding ps) //
  ((uBytes ps) c.uEncoded).size = 32 * (params ps).du * (params ps).k ∧ ((vBytes ps) c.vEncoded).size = 32 * (params ps).dv}

/-! ## `PublicKey` -/

def encodePublicKey (pk : (PublicKey ps)) : Vector UInt8 (params ps).publicKeyBytes :=
  toVecN _ ((tBytes ps) pk.1.tHatEncoded ++ ofVector pk.1.rho)

private def decodePublicKeyVal (v : Vector UInt8 (params ps).publicKeyBytes) :
    EncapsulationKey (params ps) (encoding ps) :=
  let b := ofVector v
  let a := b.extract 0 (384 * (params ps).k)
  let rest := b.extract (384 * (params ps).k) b.size
  { tHatEncoded := (bytesT ps) a, rho := toVecN 32 rest }

private theorem decodePublicKeyVal_wf (v : Vector UInt8 (params ps).publicKeyBytes) :
    ((tBytes ps) ((decodePublicKeyVal ps) v).tHatEncoded).size = 384 * (params ps).k := by
  show ((tBytes ps) ((bytesT ps) ((ofVector v).extract 0 (384 * (params ps).k)))).size = 384 * (params ps).k
  rw [(tBytes_bytesT ps), ByteArray.size_extract]
  have hb : (ofVector v).size = 384 * (params ps).k + 32 := size_ofVector v
  omega

def decodePublicKey (v : Vector UInt8 (params ps).publicKeyBytes) : Option (PublicKey ps) :=
  some ⟨(decodePublicKeyVal ps) v, (decodePublicKeyVal_wf ps) v⟩

theorem decode_encode_pub (pk : (PublicKey ps)) : (decodePublicKey ps) ((encodePublicKey ps) pk) = some pk := by
  apply congrArg some
  apply Subtype.ext
  show (decodePublicKeyVal ps) ((encodePublicKey ps) pk) = pk.val
  obtain ⟨ek, hek⟩ := pk
  obtain ⟨tHatEncoded, rho⟩ := ek
  unfold decodePublicKeyVal encodePublicKey
  dsimp only
  have hsize : ((tBytes ps) tHatEncoded ++ ofVector rho).size = (params ps).publicKeyBytes := by
    show ((tBytes ps) tHatEncoded ++ ofVector rho).size = 384 * (params ps).k + 32
    rw [ByteArray.size_append, hek, size_ofVector]
  rw [ofVector_toVecN _ hsize]
  rw [show 384 * (params ps).k = ((tBytes ps) tHatEncoded).size from hek.symm, extract_append_left]
  have hrest : ((tBytes ps) tHatEncoded ++ ofVector rho).extract ((tBytes ps) tHatEncoded).size
      ((tBytes ps) tHatEncoded ++ ofVector rho).size = ofVector rho := by
    have h := extract_append_right ((tBytes ps) tHatEncoded) (ofVector rho)
    rw [← ByteArray.size_append] at h
    exact h
  rw [hrest, toVecN_ofVector, (bytesT_tBytes ps)]

/-! ## `PrivateKey` -/

def encodePrivateKey (sk : (PrivateKey ps)) : Vector UInt8 (params ps).secretKeyBytes :=
  toVecN _ ((tBytes ps) sk.1.dkPKE.sHatEncoded ++
    ((tBytes ps) sk.1.ekPKE.tHatEncoded ++ (ofVector sk.1.ekPKE.rho ++
      (ofVector sk.1.ekHash ++ ofVector sk.1.z))))

private def decodePrivateKeyVal (v : Vector UInt8 (params ps).secretKeyBytes) :
    DecapsulationKey (params ps) (encoding ps) :=
  let b0 := ofVector v
  let sHatEncoded := b0.extract 0 (384 * (params ps).k)
  let b1 := b0.extract (384 * (params ps).k) b0.size
  let tHatEncoded := b1.extract 0 (384 * (params ps).k)
  let b2 := b1.extract (384 * (params ps).k) b1.size
  let rho := toVecN 32 (b2.extract 0 32)
  let b3 := b2.extract 32 b2.size
  let ekHash := toVecN 32 (b3.extract 0 32)
  let b4 := b3.extract 32 b3.size
  let z := toVecN 32 (b4.extract 0 32)
  { dkPKE := { sHatEncoded := (bytesT ps) sHatEncoded }
    ekPKE := { tHatEncoded := (bytesT ps) tHatEncoded, rho }, ekHash, z }

private theorem decodePrivateKeyVal_wf (v : Vector UInt8 (params ps).secretKeyBytes) :
    ((tBytes ps) ((decodePrivateKeyVal ps) v).dkPKE.sHatEncoded).size = 384 * (params ps).k ∧
    ((tBytes ps) ((decodePrivateKeyVal ps) v).ekPKE.tHatEncoded).size = 384 * (params ps).k := by
  unfold decodePrivateKeyVal
  dsimp only
  rw [(tBytes_bytesT ps), (tBytes_bytesT ps), ByteArray.size_extract, ByteArray.size_extract]
  have hb0 : (ofVector v).size = 384 * (params ps).k + (384 * (params ps).k + (32 + (32 + 32))) :=
    (size_ofVector v).trans (secretKeyBytes_eq ps)
  have hb1 : ((ofVector v).extract (384 * (params ps).k) (ofVector v).size).size
      = (ofVector v).size - 384 * (params ps).k := by
    rw [ByteArray.size_extract]; omega
  omega

def decodePrivateKey (v : Vector UInt8 (params ps).secretKeyBytes) : Option (PrivateKey ps) :=
  some ⟨(decodePrivateKeyVal ps) v, (decodePrivateKeyVal_wf ps) v⟩

theorem decode_encode_priv (sk : (PrivateKey ps)) :
    (decodePrivateKey ps) ((encodePrivateKey ps) sk) = some sk := by
  apply congrArg some
  apply Subtype.ext
  show (decodePrivateKeyVal ps) ((encodePrivateKey ps) sk) = sk.val
  obtain ⟨dk, hdkPKE, hekPKE⟩ := sk
  obtain ⟨⟨sHatEncoded⟩, ⟨tHatEncoded, rho⟩, ekHash, z⟩ := dk
  simp only at hdkPKE hekPKE
  unfold decodePrivateKeyVal encodePrivateKey
  dsimp only
  -- Fully opaque abbreviations for the five pieces — never letting `rw`/defeq-checking peek back
  -- through `tBytes`/`ofVector` into `sHatEncoded`/`rho`/etc. is what keeps the peeling below cheap.
  generalize ha1def : (tBytes ps) sHatEncoded = a1 at *
  generalize ha2def : (tBytes ps) tHatEncoded = a2 at *
  generalize ha3def : ofVector rho = a3 at *
  generalize ha4def : ofVector ekHash = a4 at *
  generalize ha5def : ofVector z = a5 at *
  have h1 : a1.size = 384 * (params ps).k := hdkPKE
  have h2 : a2.size = 384 * (params ps).k := hekPKE
  have h3 : a3.size = 32 := ha3def ▸ size_ofVector rho
  have h4 : a4.size = 32 := ha4def ▸ size_ofVector ekHash
  have h5 : a5.size = 32 := ha5def ▸ size_ofVector z
  have hsize : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).size =
      384 * (params ps).k + (384 * (params ps).k + (32 + (32 + 32))) := by
    simp only [ByteArray.size_append, h1, h2, h3, h4, h5]
  rw [secretKeyBytes_eq ps]
  rw [ofVector_toVecN _ hsize]
  have peel1 : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).extract 0 (384 * (params ps).k) = a1 := by
    rw [← h1]; exact extract_append_left _ _
  have rest1 : (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).extract (384 * (params ps).k)
      (a1 ++ (a2 ++ (a3 ++ (a4 ++ a5)))).size = a2 ++ (a3 ++ (a4 ++ a5)) := by
    have h := extract_append_right a1 (a2 ++ (a3 ++ (a4 ++ a5)))
    rw [← ByteArray.size_append, h1] at h
    exact h
  rw [peel1, rest1]
  have peel2 : (a2 ++ (a3 ++ (a4 ++ a5))).extract 0 (384 * (params ps).k) = a2 := by
    rw [← h2]; exact extract_append_left _ _
  have rest2 : (a2 ++ (a3 ++ (a4 ++ a5))).extract (384 * (params ps).k) (a2 ++ (a3 ++ (a4 ++ a5))).size
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
  rw [← ha1def, ← ha2def, ← ha3def, ← ha4def, ← ha5def, (bytesT_tBytes ps), (bytesT_tBytes ps),
    toVecN_ofVector, toVecN_ofVector, toVecN_ofVector]

/-! ## `CT` (ciphertext) -/

def encodeCiphertext (c : (CT ps)) : Vector UInt8 (params ps).ciphertextBytes :=
  toVecN _ ((uBytes ps) c.1.uEncoded ++ (vBytes ps) c.1.vEncoded)

private def decodeCiphertextVal (v : Vector UInt8 (params ps).ciphertextBytes) :
    Ciphertext (params ps) (encoding ps) :=
  let b := ofVector v
  let u := b.extract 0 (32 * (params ps).du * (params ps).k)
  let rest := b.extract (32 * (params ps).du * (params ps).k) b.size
  { uEncoded := (bytesU ps) u, vEncoded := (bytesV ps) rest }

private theorem decodeCiphertextVal_wf (v : Vector UInt8 (params ps).ciphertextBytes) :
    ((uBytes ps) ((decodeCiphertextVal ps) v).uEncoded).size = 32 * (params ps).du * (params ps).k ∧
    ((vBytes ps) ((decodeCiphertextVal ps) v).vEncoded).size = 32 * (params ps).dv := by
  unfold decodeCiphertextVal
  dsimp only
  rw [(uBytes_bytesU ps), (vBytes_bytesV ps), ByteArray.size_extract, ByteArray.size_extract]
  have hb : (ofVector v).size = 32 * (params ps).du * (params ps).k + 32 * (params ps).dv :=
    (size_ofVector v).trans (ciphertextBytes_eq ps)
  omega

def decodeCiphertext (v : Vector UInt8 (params ps).ciphertextBytes) : Option (CT ps) :=
  some ⟨(decodeCiphertextVal ps) v, (decodeCiphertextVal_wf ps) v⟩

theorem decode_encode_ct (c : (CT ps)) : (decodeCiphertext ps) ((encodeCiphertext ps) c) = some c := by
  apply congrArg some
  apply Subtype.ext
  show (decodeCiphertextVal ps) ((encodeCiphertext ps) c) = c.val
  obtain ⟨ct, hu, hv⟩ := c
  obtain ⟨uEncoded, vEncoded⟩ := ct
  simp only at hu hv
  unfold decodeCiphertextVal encodeCiphertext
  dsimp only
  have hsize : ((uBytes ps) uEncoded ++ (vBytes ps) vEncoded).size = (params ps).ciphertextBytes := by
    rw [ciphertextBytes_eq ps]
    rw [ByteArray.size_append, hu, hv]
  rw [ofVector_toVecN _ hsize]
  rw [show 32 * (params ps).du * (params ps).k = ((uBytes ps) uEncoded).size from hu.symm, extract_append_left]
  have hrest : ((uBytes ps) uEncoded ++ (vBytes ps) vEncoded).extract ((uBytes ps) uEncoded).size
      ((uBytes ps) uEncoded ++ (vBytes ps) vEncoded).size = (vBytes ps) vEncoded := by
    have h := extract_append_right ((uBytes ps) uEncoded) ((vBytes ps) vEncoded)
    rw [← ByteArray.size_append] at h
    exact h
  rw [hrest, (bytesU_uBytes ps), (bytesV_vBytes ps)]

end CryptWalker.KEM.FIPS203
