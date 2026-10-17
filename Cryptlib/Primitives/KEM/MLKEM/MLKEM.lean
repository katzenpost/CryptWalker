/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEM.Encoding
import Cryptlib.Primitives.KEM.KEM
import LatticeCrypto.MLKEM.KPKE

/-! # ML-KEM: `keygen`/`encaps`/`decaps` and the `KEM.KEM` instance

`keygen`/`encaps`/`decaps` are FIPS 203 Algorithms 19-21, written against `Primitives.primitives`
so that variants such as hedged encapsulation can change them locally.

`Reliable s` states that the draw from `s` decapsulates correctly. It is not characterized in
terms of the sampled noise. -/

namespace Cryptlib.Primitives.KEM.FIPS203

open MLKEM
open MLKEM.Concrete
open Cryptlib.Primitives.KEM.KEM (KEM KEMError)
open Cryptlib.Util.Bytes (ofVector toVecN size_ofVector ofVector_toVecN toVecN_ofVector
  extract_append_left extract_append_right)

variable (ps : ParameterSet)

/-! ## `keygen` / `encaps` / `decaps` -/

/-- `ML-KEM.KeyGen_internal`. -/
def keygen (d z : Seed32) :
    EncapsulationKey (params ps) (encoding ps) × DecapsulationKey (params ps) (encoding ps) :=
  let (ekPKE, dkPKE) := KPKE.keygenFromSeed ring (encoding ps) (primitives ps) d
  let ekHash := (primitives ps).hEncapsulationKey ekPKE.tHatEncoded ekPKE.rho
  (ekPKE, { dkPKE, ekPKE, ekHash, z })

/-- `ML-KEM.Encaps_internal`. -/
def encaps (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    SharedSecret × Ciphertext (params ps) (encoding ps) :=
  let ekHash := (primitives ps).hEncapsulationKey ek.tHatEncoded ek.rho
  let (k, r) := (primitives ps).gEncaps m ekHash
  (k, KPKE.encrypt ring (encoding ps) (primitives ps) ek m r)

/-- `ML-KEM.Decaps_internal`. Compares ciphertexts by their `ByteArray` encodings. -/
def decaps (dk : DecapsulationKey (params ps) (encoding ps)) (c : Ciphertext (params ps) (encoding ps)) :
    SharedSecret :=
  let m' := KPKE.decrypt ring (encoding ps) (primitives ps) dk.dkPKE c
  let (k', r') := (primitives ps).gEncaps m' dk.ekHash
  let kBar := (primitives ps).jReject dk.z c.uEncoded c.vEncoded
  let c' := KPKE.encrypt ring (encoding ps) (primitives ps) dk.ekPKE m' r'
  if (uBytes ps) c.uEncoded = (uBytes ps) c'.uEncoded ∧ (vBytes ps) c.vEncoded = (vBytes ps) c'.vEncoded then k'
  else kBar

/-! ## FIPS 203 §7.2/§7.3 input-validation checks

The internal algorithms above do not validate keys; callers run these checks first. -/

/-- FIPS 203 §7.2 modulus check: `tHatEncoded` survives a decode/encode round trip. -/
def checkEncapsulationKey (ek : EncapsulationKey (params ps) (encoding ps)) : Bool :=
  (tBytes ps) ((encoding ps).byteEncode12Vec ((encoding ps).byteDecode12Vec ek.tHatEncoded)) == (tBytes ps) ek.tHatEncoded

/-- FIPS 203 §7.3 hash check: `dk.ekHash = H(ekPKE)`. -/
def checkDecapsulationKey (dk : DecapsulationKey (params ps) (encoding ps)) : Bool :=
  ofVector ((primitives ps).hEncapsulationKey dk.ekPKE.tHatEncoded dk.ekPKE.rho) == ofVector dk.ekHash

/-! ## `keygen`/`encaps` outputs are well-formed -/

theorem keygen_ek_wf (d z : Seed32) :
    ((tBytes ps) ((keygen ps) d z).1.tHatEncoded).size = 384 * (params ps).k := by
  unfold keygen KPKE.keygenFromSeed
  dsimp only
  show ((tBytes ps) ((encoding ps).byteEncode12Vec _)).size = 384 * (params ps).k
  unfold tBytes
  show ((encoding ps).byteEncode12Vec _ : ByteArray).size = 384 * (params ps).k
  exact concreteEncoding_byteEncode12Vec_size (params ps) _

theorem keygen_dk_wf (d z : Seed32) :
    ((tBytes ps) ((keygen ps) d z).2.dkPKE.sHatEncoded).size = 384 * (params ps).k ∧
      ((tBytes ps) ((keygen ps) d z).2.ekPKE.tHatEncoded).size = 384 * (params ps).k := by
  constructor
  · unfold keygen KPKE.keygenFromSeed
    dsimp only
    show ((tBytes ps) ((encoding ps).byteEncode12Vec _)).size = 384 * (params ps).k
    unfold tBytes
    show ((encoding ps).byteEncode12Vec _ : ByteArray).size = 384 * (params ps).k
    exact concreteEncoding_byteEncode12Vec_size (params ps) _
  · exact (keygen_ek_wf ps) d z

private theorem encaps_ct_wf (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    ((uBytes ps) ((encaps ps) ek m).2.uEncoded).size = 32 * (params ps).du * (params ps).k ∧
      ((vBytes ps) ((encaps ps) ek m).2.vEncoded).size = 32 * (params ps).dv := by
  unfold encaps KPKE.encrypt
  dsimp only
  refine ⟨?_, ?_⟩
  · show ((encoding ps).byteEncodeDUVec _ : ByteArray).size = 32 * (params ps).du * (params ps).k
    exact encoding_byteEncodeDUVec_size ps _
  · show ((encoding ps).byteEncodeDV _ : ByteArray).size = 32 * (params ps).dv
    exact concreteEncoding_byteEncodeDV_size (params ps) _

/-! ## `State`: a SHAKE-256 stream of 32-byte blocks from one 32-byte seed -/

/-- The `i`-th 32-byte block derived from `seed`. -/
def seedBlock (seed : Vector UInt8 32) (i : Nat) : Vector UInt8 32 :=
  toVecN 32 (SLHDSA.Concrete.Keccak.shake256 (ofVector seed |>.push i.toUInt8) 32)

/-- Counter plus the original seed. -/
abbrev State := Nat × Vector UInt8 32

def nextDraw : EStateM KEMError State (Vector UInt8 32) :=
  fun (i, seed) => .ok (seedBlock seed i) (i + 1, seed)

def stateFromSeed (seed : Vector UInt8 32) : State := (0, seed)

/-! ## The `KEM.KEM` instance -/

/-- The next draw from `s`, encapsulated against any key pair, decapsulates correctly. -/
def Reliable (s : State) : Prop :=
  ∀ (dk : DecapsulationKey (params ps) (encoding ps)) (ek : EncapsulationKey (params ps) (encoding ps)),
    ek = dk.ekPKE →
    (decaps ps) dk ((encaps ps) ek (seedBlock s.2 s.1)).2 = ((encaps ps) ek (seedBlock s.2 s.1)).1

def encapM (pk : (PublicKey ps)) : EStateM KEMError State ((CT ps) × Vector UInt8 32) := do
  let m ← nextDraw
  pure (⟨((encaps ps) pk.1 m).2, (encaps_ct_wf ps) pk.1 m⟩, ((encaps ps) pk.1 m).1)

def decapM (sk : (PrivateKey ps)) (c : (CT ps)) : EStateM KEMError State (Vector UInt8 32) :=
  pure ((decaps ps) sk.1 c.1)

def derivePublicKeyM (sk : (PrivateKey ps)) : (PublicKey ps) := ⟨sk.1.ekPKE, sk.2.2⟩

/-- Round trip from a `Reliable` state. Uses `simp only` on `hc`; `injection` times out on the
`CT` subtype. -/
theorem honestRoundTripM (sk : (PrivateKey ps)) (s : State) (hrel : (Reliable ps) s)
    (c : (CT ps)) (k : Vector UInt8 32) (s' : State)
    (hc : (encapM ps) ((derivePublicKeyM ps) sk) s = .ok (c, k) s') (t : State) :
    ∃ t', (decapM ps) sk c t = .ok k t' := by
  obtain ⟨i, seed⟩ := s
  simp only [encapM, nextDraw, bind, EStateM.bind, EStateM.pure, pure,
    EStateM.Result.ok.injEq, Prod.mk.injEq] at hc
  obtain ⟨⟨hc1, hc2⟩, _hc3⟩ := hc
  refine ⟨t, ?_⟩
  unfold decapM
  rw [← hc1, hrel sk.1 ((derivePublicKeyM ps) sk).1 rfl, hc2]
  rfl

theorem decodePrivateKey_totalM (v : Vector UInt8 (params ps).secretKeyBytes) :
    ∃ sk : (PrivateKey ps), (decodePrivateKey ps) v = some sk := by
  unfold decodePrivateKey
  exact ⟨_, rfl⟩

def dummySeed : Seed32 := Vector.replicate 32 0

def dummyPk : (PublicKey ps) := ⟨((keygen ps) dummySeed dummySeed).1, (keygen_ek_wf ps) _ _⟩

def dummySk : (PrivateKey ps) := ⟨((keygen ps) dummySeed dummySeed).2, (keygen_dk_wf ps) _ _⟩

def dummyCt : (CT ps) := ⟨((encaps ps) (dummyPk ps).1 dummySeed).2, (encaps_ct_wf ps) _ _⟩

/-- ML-KEM with the expanded FIPS 203 private key. -/
def kem : KEM where
  State := State
  PublicKey := (PublicKey ps)
  PrivateKey := (PrivateKey ps)
  Ciphertext := (CT ps)
  Plaintext := Vector UInt8 32

  pubI := ⟨(dummyPk ps)⟩
  privI := ⟨(dummySk ps)⟩
  ctI := ⟨(dummyCt ps)⟩
  ptI := ⟨Vector.replicate 32 0⟩
  stateI := ⟨(0, dummySeed)⟩

  publicKeySize := (params ps).publicKeyBytes
  privateKeySize := (params ps).secretKeyBytes
  ciphertextSize := (params ps).ciphertextBytes
  plaintextSize := 32

  encodePublicKey := (encodePublicKey ps)
  decodePublicKey := (decodePublicKey ps)
  encodePrivateKey := (encodePrivateKey ps)
  decodePrivateKey := (decodePrivateKey ps)
  encodeCiphertext := (encodeCiphertext ps)
  decodeCiphertext := (decodeCiphertext ps)
  encodePlaintext := id

  decap := (decapM ps)
  encap := (encapM ps)
  Reliable := (Reliable ps)
  generate := do
    let d ← nextDraw
    let z ← nextDraw
    let ekPKE := ((keygen ps) d z).1
    let pk : (PublicKey ps) := ⟨ekPKE, (keygen_ek_wf ps) d z⟩
    let sk : (PrivateKey ps) := ⟨((keygen ps) d z).2, (keygen_dk_wf ps) d z⟩
    have hpk : pk = (derivePublicKeyM ps) sk := Subtype.ext rfl
    pure ⟨pk, sk, hpk ▸ (honestRoundTripM ps) sk⟩
  stateFromSeed := stateFromSeed
  derivePublicKey := (derivePublicKeyM ps)
  honestRoundTrip := (honestRoundTripM ps)
  decodePrivateKey_total := (decodePrivateKey_totalM ps)

  decode_encode_pub := (decode_encode_pub ps)
  decode_encode_priv := (decode_encode_priv ps)
  decode_encode_ct := (decode_encode_ct ps)

  plaintextEq := inferInstance

/-! ## Seed-format private keys

`kemSeed` stores the private key as the seed `(d, z)`, encoded `ek ‖ d ‖ z`, and re-expands it on
use. Everything else is as in `kem`. -/

abbrev SeedPrivateKey := Seed32 × Seed32

def derivePublicKeyFromSeed (sk : SeedPrivateKey) : (PublicKey ps) :=
  ⟨((keygen ps) sk.1 sk.2).1, (keygen_ek_wf ps) sk.1 sk.2⟩

/-- The expanded decapsulation key for a seed, recomputed on every call. -/
def expandSeed (sk : SeedPrivateKey) : (PrivateKey ps) :=
  ⟨((keygen ps) sk.1 sk.2).2, (keygen_dk_wf ps) sk.1 sk.2⟩

def decapMFromSeed (sk : SeedPrivateKey) (c : (CT ps)) : EStateM KEMError State (Vector UInt8 32) :=
  (decapM ps) ((expandSeed ps) sk) c

theorem honestRoundTripFromSeed (sk : SeedPrivateKey) : ∀ s, (Reliable ps) s → ∀ c k s',
    (encapM ps) ((derivePublicKeyFromSeed ps) sk) s = .ok (c, k) s' → ∀ t, ∃ t', (decapMFromSeed ps) sk c t = .ok k t' :=
  (honestRoundTripM ps) ((expandSeed ps) sk)

def encodePrivateKeyFromSeed (sk : SeedPrivateKey) : Vector UInt8 ((params ps).publicKeyBytes + 64) :=
  toVecN _
    (ofVector ((encodePublicKey ps) ((derivePublicKeyFromSeed ps) sk)) ++ (ofVector sk.1 ++ ofVector sk.2))

def decodePrivateKeyFromSeed (v : Vector UInt8 ((params ps).publicKeyBytes + 64)) :
    Option SeedPrivateKey :=
  let b := ofVector v
  let rest := b.extract (params ps).publicKeyBytes b.size
  some (toVecN 32 (rest.extract 0 32), toVecN 32 (rest.extract 32 rest.size))

theorem decodePrivateKeyFromSeed_total (v : Vector UInt8 ((params ps).publicKeyBytes + 64)) :
    ∃ sk, (decodePrivateKeyFromSeed ps) v = some sk := ⟨_, rfl⟩

theorem decode_encode_privFromSeed (sk : SeedPrivateKey) :
    (decodePrivateKeyFromSeed ps) ((encodePrivateKeyFromSeed ps) sk) = some sk := by
  obtain ⟨d, z⟩ := sk
  unfold encodePrivateKeyFromSeed decodePrivateKeyFromSeed
  dsimp only
  generalize hekdef : ofVector ((encodePublicKey ps) ((derivePublicKeyFromSeed ps) (d, z))) = ek
  have hek : ek.size = (params ps).publicKeyBytes := by rw [← hekdef]; exact size_ofVector _
  have hd : (ofVector d).size = 32 := size_ofVector _
  have hz : (ofVector z).size = 32 := size_ofVector _
  have hsize : (ek ++ (ofVector d ++ ofVector z)).size = (params ps).publicKeyBytes + 64 := by
    rw [ByteArray.size_append, ByteArray.size_append, hek, hd, hz]
  rw [ofVector_toVecN _ hsize]
  have hrest : (ek ++ (ofVector d ++ ofVector z)).extract (params ps).publicKeyBytes
      (ek ++ (ofVector d ++ ofVector z)).size = ofVector d ++ ofVector z := by
    have h := extract_append_right ek (ofVector d ++ ofVector z)
    rw [← ByteArray.size_append, hek] at h
    exact h
  rw [hrest]
  have hpeel1 : (ofVector d ++ ofVector z).extract 0 32 = ofVector d := by
    have h := extract_append_left (ofVector d) (ofVector z)
    rwa [hd] at h
  have hpeel2 : (ofVector d ++ ofVector z).extract 32 (ofVector d ++ ofVector z).size
      = ofVector z := by
    have h := extract_append_right (ofVector d) (ofVector z)
    rw [hd] at h
    rw [ByteArray.size_append, hd]
    exact h
  rw [hpeel1, hpeel2, toVecN_ofVector, toVecN_ofVector]

/-- ML-KEM with the `ek ‖ d ‖ z` seed private key. -/
def kemSeed : KEM where
  State := State
  PublicKey := (PublicKey ps)
  PrivateKey := SeedPrivateKey
  Ciphertext := (CT ps)
  Plaintext := Vector UInt8 32

  pubI := ⟨(dummyPk ps)⟩
  privI := ⟨(dummySeed, dummySeed)⟩
  ctI := ⟨(dummyCt ps)⟩
  ptI := ⟨Vector.replicate 32 0⟩
  stateI := ⟨(0, dummySeed)⟩

  publicKeySize := (params ps).publicKeyBytes
  privateKeySize := (params ps).publicKeyBytes + 64
  ciphertextSize := (params ps).ciphertextBytes
  plaintextSize := 32

  encodePublicKey := (encodePublicKey ps)
  decodePublicKey := (decodePublicKey ps)
  encodePrivateKey := (encodePrivateKeyFromSeed ps)
  decodePrivateKey := (decodePrivateKeyFromSeed ps)
  encodeCiphertext := (encodeCiphertext ps)
  decodeCiphertext := (decodeCiphertext ps)
  encodePlaintext := id

  decap := (decapMFromSeed ps)
  encap := (encapM ps)
  Reliable := (Reliable ps)
  generate := do
    let d ← nextDraw
    let z ← nextDraw
    pure ⟨(derivePublicKeyFromSeed ps) (d, z), (d, z), (honestRoundTripFromSeed ps) (d, z)⟩
  stateFromSeed := stateFromSeed
  derivePublicKey := (derivePublicKeyFromSeed ps)
  honestRoundTrip := (honestRoundTripFromSeed ps)
  decodePrivateKey_total := (decodePrivateKeyFromSeed_total ps)

  decode_encode_pub := (decode_encode_pub ps)
  decode_encode_priv := (decode_encode_privFromSeed ps)
  decode_encode_ct := (decode_encode_ct ps)

  plaintextEq := inferInstance

end Cryptlib.Primitives.KEM.FIPS203
