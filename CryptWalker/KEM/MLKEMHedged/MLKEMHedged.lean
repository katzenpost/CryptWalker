/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM
import CryptWalker.KEM.KEM
import LatticeCrypto.MLKEM.KPKE

/-! # Hedged ML-KEM, every parameter set: restoring round-3 Kyber's `m ← H(m)` pre-hash

FIPS 203's `ML-KEM.Encaps_internal` derives its encryption coins as `G(m ‖ H(ek))`, straight from
the freshly-sampled message `m`. Round-3 Kyber, the predecessor CRYSTALS-Kyber submission FIPS 203
is drawn from, first replaced `m` with `H(m)` — a hedge against a weak or structured RNG, since the
derived coins and the encrypted plaintext both then depend on the sampled `m` only through its
hash, not on `m` itself. FIPS 203 dropped that step. This file restores it, for each FIPS 203
parameter set.

Named `MLKEMHedged` rather than `MLKEM...`: this is deliberately *not* the standardized scheme. It
does not match FIPS 203 and must never be confused with it.

## What changes, and why decapsulation does not

Only `encapsHedged` differs from `FIPS203.encaps`: it hashes `m` before deriving `(k, r)` and
before it is the plaintext `KPKE.encrypt` seals. Decapsulation needs no analogous change and none
is made — `FIPS203.decaps` already treats whatever `KPKE.decrypt` recovers as "the message"
without caring what it represents; here that is simply `H(m)` rather than `m`. Key generation and
wire encoding are untouched, so `FIPS203`'s are reused directly. -/

namespace CryptWalker.KEM.MLKEMHedged

open MLKEM
open MLKEM.Concrete
open CryptWalker.KEM.KEM (KEM KEMError)
open CryptWalker.KEM.FIPS203
open CryptWalker.Util.Bytes (ofVector)

variable (ps : ParameterSet)

/-! ## `encapsHedged`: the one place the two schemes differ -/

/-- `ML-KEM.Encaps_internal`, with round-3 Kyber's `m ← H(m)` restored: hash the sampled message
before it is used for anything. `H` is `FIPS203.hashH`, SHA3-256, the same hash FIPS 203 itself
uses for `H(ek)` — round-3 Kyber used the identical function for both. -/
def encapsHedged (ek : EncapsulationKey (params ps) (encoding ps)) (m : Message) :
    SharedSecret × Ciphertext (params ps) (encoding ps) :=
  let mh : Message := hashH (ofVector m)
  let ekHash := (primitives ps).hEncapsulationKey ek.tHatEncoded ek.rho
  let (k, r) := (primitives ps).gEncaps mh ekHash
  (k, KPKE.encrypt ring (encoding ps) (primitives ps) ek mh r)

/-- Hedged encapsulation is exactly FIPS 203's `Encaps_internal` (`FIPS203.encaps`) applied to
`H(m)`. This is why NIST's ACVP encapsulation vectors, which give `Encaps_internal`'s input
directly, check the hedged scheme everywhere except the pre-hash itself. -/
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

/-! ## `State`, `Reliable`, and the `KEM.KEM` instance

`State` and randomness (`seedBlock`/`nextDraw`/`stateFromSeed`) are exactly `FIPS203`'s — hedging
draws no extra randomness, it only reroutes `m` through a hash before use. -/

/-- `s` is `Reliable` when the draw it would next produce, encapsulated with `encapsHedged`
against any keypair, decapsulates back correctly — the same operational statement as
`FIPS203.Reliable`, for `encapsHedged`/`decaps` instead of `encaps`/`decaps`. See
`FIPS203`'s module doc for why this is stated operationally rather than via a checkable noise
bound: everything said there about ML-KEM's CBD noise applies unchanged here, since hedging affects
which message is encrypted, not the noise the encryption itself introduces. -/
def Reliable (s : State) : Prop :=
  ∀ (dk : DecapsulationKey (params ps) (encoding ps)) (ek : EncapsulationKey (params ps) (encoding ps)),
    ek = dk.ekPKE →
    (decaps ps) dk ((encapsHedged ps) ek (seedBlock s.2 s.1)).2
      = ((encapsHedged ps) ek (seedBlock s.2 s.1)).1

def encapM (pk : (PublicKey ps)) : EStateM KEMError State ((CT ps) × Vector UInt8 32) := do
  let m ← nextDraw
  pure (⟨((encapsHedged ps) pk.1 m).2, (encapsHedged_ct_wf ps) pk.1 m⟩, ((encapsHedged ps) pk.1 m).1)

/-- As `FIPS203.honestRoundTripM` — see its docstring for why the proof goes through `simp only`
unfolding rather than `injection` on `CT`'s subtype. -/
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

/-- The assembled `KEM.KEM` instance for hedged ML-KEM. `decap`, key generation and every
encode/decode function are `FIPS203`'s, unchanged; only `encap`, `Reliable` and the round-trip
witness are this file's own. The 768 instance is registered in `KEM/Schemes.lean` as
`"MLKEM768Hedged"`. -/
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

As `FIPS203.kemSeed`: the private key is `(d, z)`, encoded `ek ‖ d ‖ z`, so both schemes'
seed instances share one key format. -/

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
