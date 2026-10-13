/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM
import CryptWalker.KEM.KEM
import LatticeCrypto.MLKEM.KPKE

/-! # Hedged ML-KEM: round-3 Kyber's `m ← H(m)` pre-hash

Encapsulation replaces the sampled message `m` with `H(m)` before deriving coins and encrypting,
hedging against a weak RNG. This is not FIPS 203. Decapsulation, key generation and encodings are
`FIPS203`'s. -/

namespace CryptWalker.KEM.MLKEMHedged

open MLKEM
open MLKEM.Concrete
open CryptWalker.KEM.KEM (KEM KEMError)
open CryptWalker.KEM.FIPS203
open CryptWalker.Util.Bytes (ofVector)

variable (ps : ParameterSet)

/-! ## `encapsHedged` -/

/-- `ML-KEM.Encaps_internal` on `H(m)`, with `H` = SHA3-256. -/
def encapsHedged (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    SharedSecret × Ciphertext (params ps) (encoding ps) :=
  let mh : Message := hashH (ofVector m)
  let ekHash := (primitives ps).hEncapsulationKey ek.tHatEncoded ek.rho
  let (k, r) := (primitives ps).gEncaps mh ekHash
  (k, KPKE.encrypt ring (encoding ps) (primitives ps) ek mh r)

/-- Hedged encapsulation is `FIPS203.encaps` applied to `H(m)`. -/
theorem encapsHedged_eq_encaps_hashH (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    (encapsHedged ps) ek m
      = FIPS203.encaps ps ek (hashH (ofVector m)) :=
  rfl

private theorem encapsHedged_ct_wf (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    ((uBytes ps) ((encapsHedged ps) ek m).2.uEncoded).size = 32 * (params ps).du * (params ps).k ∧
      ((vBytes ps) ((encapsHedged ps) ek m).2.vEncoded).size = 32 * (params ps).dv := by
  unfold encapsHedged KPKE.encrypt
  dsimp only
  refine ⟨?_, ?_⟩
  · show ((encoding ps).byteEncodeDUVec _ : ByteArray).size = 32 * (params ps).du * (params ps).k
    exact encoding_byteEncodeDUVec_size ps _
  · show ((encoding ps).byteEncodeDV _ : ByteArray).size = 32 * (params ps).dv
    exact concreteEncoding_byteEncodeDV_size (params ps) _

/-! ## The `KEM.KEM` instance

`State` and randomness are `FIPS203`'s. -/

/-- The next draw from `s`, encapsulated with `encapsHedged` against any key pair, decapsulates
correctly. -/
def Reliable (s : State) : Prop :=
  ∀ (dk : DecapsulationKey (params ps) (encoding ps)) (ek : EncapsulationKey (params ps) (encoding ps)),
    ek = dk.ekPKE →
    (decaps ps) dk ((encapsHedged ps) ek (seedBlock s.2 s.1)).2
      = ((encapsHedged ps) ek (seedBlock s.2 s.1)).1

def encapM (pk : (PublicKey ps)) : EStateM KEMError State ((CT ps) × Vector UInt8 32) := do
  let m ← nextDraw
  pure (⟨((encapsHedged ps) pk.1 m).2, (encapsHedged_ct_wf ps) pk.1 m⟩, ((encapsHedged ps) pk.1 m).1)

/-- Round trip from a `Reliable` state, as `FIPS203.honestRoundTripM`. -/
theorem honestRoundTripM (sk : (PrivateKey ps)) (s : State) (hrel : (Reliable ps) s)
    (c : (CT ps)) (k : Vector UInt8 32) (s' : State)
    (hc : (encapM ps) ((derivePublicKeyM ps) sk) s = .ok (c, k) s') (t : State) :
    ∃ t', (decapM ps) sk c t = .ok k t' := by
  obtain ⟨i, seed⟩ := s
  simp only [encapM, nextDraw, bind, EStateM.bind, EStateM.pure, pure,
    EStateM.Result.ok.injEq, Prod.mk.injEq] at hc
  obtain ⟨⟨hc1, hc2⟩, _hc3⟩ := hc
  refine ⟨t, ?_⟩
  have h := hrel sk.1 ((derivePublicKeyM ps) sk).1 rfl
  unfold FIPS203.decapM
  rw [← hc1, h, hc2]
  rfl

/-- Hedged ML-KEM with the expanded FIPS 203 private key. -/
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

/-! ## Seed-format private keys, as in `FIPS203.kemSeed` -/

theorem honestRoundTripFromSeed (sk : SeedPrivateKey) : ∀ s, (Reliable ps) s → ∀ c k s',
    (encapM ps) ((derivePublicKeyFromSeed ps) sk) s = .ok (c, k) s' → ∀ t, ∃ t', (decapMFromSeed ps) sk c t = .ok k t' :=
  (honestRoundTripM ps) ((expandSeed ps) sk)

/-- Hedged ML-KEM with `FIPS203.kemSeed`'s private-key format. -/
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

end CryptWalker.KEM.MLKEMHedged
