/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM768
import CryptWalker.KEM.KEM
import LatticeCrypto.MLKEM.KPKE

/-! # ML-KEM-768, hedged: restoring round-3 Kyber's `m ← H(m)` pre-hash

FIPS 203's `ML-KEM.Encaps_internal` derives its encryption coins as `G(m ‖ H(ek))`, straight from
the freshly-sampled message `m`. Round-3 Kyber, the predecessor CRYSTALS-Kyber submission FIPS 203
is drawn from, first replaced `m` with `H(m)` — a hedge against a weak or structured RNG, since the
derived coins and the encrypted plaintext both then depend on the sampled `m` only through its
hash, not on `m` itself. FIPS 203 dropped that step. This file restores it, exactly as
`MLKEM768.lean`'s own module doc anticipated: "owning this layer means a future variant restoring
that pre-hash is a small, local change here, not a fork of vendored code."

Named `MLKEMHedged` rather than `MLKEM...` — `MLKEM768` (this project's own FIPS 203 conformant
instance) already owns that name, and this is deliberately *not* that scheme: it does not match
FIPS 203, has no test vectors (there is no standard to check it against), and must never be
confused with the standardized one.

## What changes, and why decapsulation does not

Only `encaps768Hedged` differs from `MLKEM768.encaps768`: it hashes `m` before deriving `(k, r)`
and before it is the plaintext `KPKE.encrypt` seals. Decapsulation needs no analogous change and
none is made — `MLKEM768.decaps768` already treats whatever `KPKE.decrypt` recovers as "the
message" without caring what it represents; here that is simply `H(m)` rather than `m`. Key
generation is untouched by either scheme, so `MLKEM768.keygen768` is reused directly. Everything
about wire encoding (`PublicKey`, `PrivateKey`, `CT`, and their `encode`/`decode` pairs) is
likewise unaffected by which hash composition produced a ciphertext's bytes, so `MLKEM768Encoding`
is reused unchanged. -/

namespace CryptWalker.KEM.MLKEMHedged

open MLKEM
open MLKEM.Concrete
open CryptWalker.KEM.KEM (KEM KEMError)
open CryptWalker.KEM.MLKEM768 (params encoding primitives ring PublicKey PrivateKey CT State
  seedBlock nextDraw stateFromSeed keygen768 keygen768_ek_wf keygen768_dk_wf decaps768 decapM
  derivePublicKeyM encodePublicKey decodePublicKey encodePrivateKey decodePrivateKey
  encodeCiphertext decodeCiphertext decode_encode_pub decode_encode_priv decode_encode_ct
  decodePrivateKey_totalM dummySeed dummyPk dummySk dummyCt uBytes vBytes)
open CryptWalker.Util.Bytes (ofVector)

/-! ## `encaps768Hedged`: the one place the two schemes differ -/

/-- `ML-KEM.Encaps_internal`, with round-3 Kyber's `m ← H(m)` restored: hash the sampled message
before it is used for anything. `H` is `MLKEM768.hashH`, SHA3-256, the same hash FIPS 203 itself
uses for `H(ek)` — round-3 Kyber used the identical function for both. -/
def encaps768Hedged (ek : EncapsulationKey params encoding) (m : Message) :
    SharedSecret × Ciphertext params encoding :=
  let mh : Message := CryptWalker.KEM.MLKEM768.hashH (ofVector m)
  let ekHash := primitives.hEncapsulationKey ek.tHatEncoded ek.rho
  let (k, r) := primitives.gEncaps mh ekHash
  (k, KPKE.encrypt ring encoding primitives ek mh r)

private theorem encaps768Hedged_ct_wf (ek : EncapsulationKey params encoding) (m : Message) :
    (uBytes (encaps768Hedged ek m).2.uEncoded).size = 32 * params.du * params.k ∧
      (vBytes (encaps768Hedged ek m).2.vEncoded).size = 32 * params.dv := by
  unfold encaps768Hedged KPKE.encrypt
  dsimp only
  refine ⟨?_, ?_⟩
  · show (encoding.byteEncodeDUVec _ : ByteArray).size = 32 * params.du * params.k
    exact concreteEncoding_byteEncodeDUVec_size params _
  · show (encoding.byteEncodeDV _ : ByteArray).size = 32 * params.dv
    exact concreteEncoding_byteEncodeDV_size params _

/-! ## `State`, `Reliable`, and the `KEM.KEM` instance

`State` and randomness (`seedBlock`/`nextDraw`/`stateFromSeed`) are exactly `MLKEM768`'s — hedging
draws no extra randomness, it only reroutes `m` through a hash before use. -/

/-- `s` is `Reliable` when the draw it would next produce, encapsulated with `encaps768Hedged`
against any keypair, decapsulates back correctly — the same operational statement as
`MLKEM768.Reliable`, for `encaps768Hedged`/`decaps768` instead of `encaps768`/`decaps768`. See
`MLKEM768`'s module doc for why this is stated operationally rather than via a checkable noise
bound: everything said there about ML-KEM's CBD noise applies unchanged here, since hedging affects
which message is encrypted, not the noise the encryption itself introduces. -/
def Reliable (s : State) : Prop :=
  ∀ (dk : DecapsulationKey params encoding) (ek : EncapsulationKey params encoding),
    ek = dk.ekPKE →
    decaps768 dk (encaps768Hedged ek (seedBlock s.2 s.1)).2
      = (encaps768Hedged ek (seedBlock s.2 s.1)).1

def encapM (pk : PublicKey) : EStateM KEMError State (CT × Vector UInt8 32) := do
  let m ← nextDraw
  pure (⟨(encaps768Hedged pk.1 m).2, encaps768Hedged_ct_wf pk.1 m⟩, (encaps768Hedged pk.1 m).1)

/-- As `MLKEM768.honestRoundTripM` — see its docstring for why the proof goes through `simp only`
unfolding rather than `injection` on `CT`'s subtype. -/
theorem honestRoundTripM (sk : PrivateKey) (s : State) (hrel : Reliable s)
    (c : CT) (k : Vector UInt8 32) (s' : State)
    (hc : encapM (derivePublicKeyM sk) s = .ok (c, k) s') (t : State) :
    ∃ t', decapM sk c t = .ok k t' := by
  obtain ⟨i, seed⟩ := s
  simp only [encapM, nextDraw, bind, EStateM.bind, EStateM.pure, pure,
    EStateM.Result.ok.injEq, Prod.mk.injEq] at hc
  obtain ⟨⟨hc1, hc2⟩, _hc3⟩ := hc
  refine ⟨t, ?_⟩
  unfold decapM
  rw [← hc1, hrel sk.1 (derivePublicKeyM sk).1 rfl, hc2]
  rfl

/-- The assembled `KEM.KEM` instance for hedged ML-KEM-768. `decap`, key generation and every
encode/decode function are `MLKEM768`'s, unchanged; only `encap`, `Reliable` and the round-trip
witness are this file's own.

Not registered in `KEM/Schemes.lean`: it has no NIST vectors (it isn't FIPS 203) and no `hpqc`
counterpart to cross-check against, unlike every scheme that registry lists. -/
def kemMLKEMHedged768 : KEM where
  State := State
  PublicKey := PublicKey
  PrivateKey := PrivateKey
  Ciphertext := CT
  Plaintext := Vector UInt8 32

  pubI := ⟨dummyPk⟩
  privI := ⟨dummySk⟩
  ctI := ⟨dummyCt⟩
  ptI := ⟨Vector.replicate 32 0⟩
  stateI := ⟨(0, dummySeed)⟩

  publicKeySize := params.publicKeyBytes
  privateKeySize := params.secretKeyBytes
  ciphertextSize := params.ciphertextBytes
  plaintextSize := 32

  encodePublicKey := encodePublicKey
  decodePublicKey := decodePublicKey
  encodePrivateKey := encodePrivateKey
  decodePrivateKey := decodePrivateKey
  encodeCiphertext := encodeCiphertext
  decodeCiphertext := decodeCiphertext
  encodePlaintext := id

  decap := decapM
  encap := encapM
  Reliable := Reliable
  generate := do
    let d ← nextDraw
    let z ← nextDraw
    let ekPKE := (keygen768 d z).1
    let pk : PublicKey := ⟨ekPKE, keygen768_ek_wf d z⟩
    let sk : PrivateKey := ⟨(keygen768 d z).2, keygen768_dk_wf d z⟩
    have hpk : pk = derivePublicKeyM sk := Subtype.ext rfl
    pure ⟨pk, sk, hpk ▸ honestRoundTripM sk⟩
  stateFromSeed := stateFromSeed
  derivePublicKey := derivePublicKeyM
  honestRoundTrip := honestRoundTripM
  decodePrivateKey_total := decodePrivateKey_totalM

  decode_encode_pub := decode_encode_pub
  decode_encode_priv := decode_encode_priv
  decode_encode_ct := decode_encode_ct

  plaintextEq := inferInstance

end CryptWalker.KEM.MLKEMHedged
