/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM768Encoding
import CryptWalker.KEM.KEM
import LatticeCrypto.MLKEM.KPKE

/-! # ML-KEM-768: our own `keygen`/`encaps`/`decaps`, and the `KEM.KEM` instance

`keygen768`/`encaps768`/`decaps768` mirror FIPS 203 Algorithms 19-21 exactly (the same shape as
VCVio's own `MLKEM.keygenInternal`/`encapsInternal`/`decapsInternal`, confirmed by reading
`LatticeCrypto/MLKEM/Internal.lean`), but are our own code, built directly from `KPKE.keygenFromSeed`/
`encrypt`/`decrypt` and `MLKEM768Primitives.primitives`'s hash fields — not a call into VCVio's
`Internal.lean`. This is deliberate: this thin hash-composition layer is exactly where FIPS 203
differs from round-3 Kyber (which hashed the freshly-sampled encapsulation message through itself,
`m ← H(m)`, before deriving encryption coins — a hedge against weak/structured randomness that
FIPS 203 dropped). Owning this layer means a future variant restoring that pre-hash is a small,
local change here, not a fork of vendored code.

## `Reliable`, stated honestly

`KPKE.decrypt`'s correctness depends on the accumulated noise (from both keygen's own secret/error
vectors *and* encaps's own coins) staying under FIPS 203's decoding margin — and unlike a
Diffie-Hellman KEM, this genuinely cannot be guaranteed for every possible draw: ML-KEM's CBD
noise is individually bounded but *not* worst-case boundable in aggregate without also invoking
just how unlikely a bad combination is (that's exactly why FIPS 203 publishes a nonzero, if
negligible, decryption-failure probability rather than a hard bound). Deriving a checkable
arithmetic characterization of exactly when the aggregate noise stays small enough is a serious,
dedicated piece of lattice-cryptography formalization on its own (comparable to what a standalone
paper establishes for Kyber's correctness bound) — well beyond this bridge's scope.

So `Reliable` here is stated *operationally*: "the specific draw this state would produce
decapsulates correctly against any keypair it's used with" — directly the round-trip property,
not a lower-level noise bound. This is the same style VCVio's own `VCVio.CryptoFoundations.
KeyEncapMech.PerfectlyCorrect` already uses (`Pr[CorrectExp] = 1`, an operational experiment, not
an arithmetic characterization), just restated as a plain `Prop` to match this project's
deterministic `EStateM` model rather than a probability space. It is not circular or vacuous —
`Reliable s` is a genuine, checkable (in principle, by running the computation) fact about a
specific state, it is simply not yet *characterized* here in terms of the underlying noise
polynomials' coefficients. That characterization — and separately, bounding how often `Reliable`
actually holds — is exactly the follow-on work this file's `Reliable` definition is designed to
make room for, without blocking a working, honest ML-KEM-768 `KEM.KEM` instance today. -/

namespace CryptWalker.KEM.MLKEM768

open MLKEM
open MLKEM.Concrete
open CryptWalker.KEM.KEM (KEM KEMError)
open CryptWalker.Util.Bytes (ofVector toVecN size_ofVector ofVector_toVecN toVecN_ofVector
  extract_append_left extract_append_right)

/-! ## `keygen768` / `encaps768` / `decaps768` -/

/-- `ML-KEM.KeyGen_internal`, our own copy — see the module doc. -/
def keygen768 (d z : Seed32) :
    EncapsulationKey params encoding × DecapsulationKey params encoding :=
  let (ekPKE, dkPKE) := KPKE.keygenFromSeed ring encoding primitives d
  let ekHash := primitives.hEncapsulationKey ekPKE.tHatEncoded ekPKE.rho
  (ekPKE, { dkPKE, ekPKE, ekHash, z })

/-- `ML-KEM.Encaps_internal`, our own copy. -/
def encaps768 (ek : EncapsulationKey params encoding) (m : Message) :
    SharedSecret × Ciphertext params encoding :=
  let ekHash := primitives.hEncapsulationKey ek.tHatEncoded ek.rho
  let (k, r) := primitives.gEncaps m ekHash
  (k, KPKE.encrypt ring encoding primitives ek m r)

/-- `ML-KEM.Decaps_internal`, our own copy. Compares ciphertexts componentwise on their
`ByteArray` encodings rather than via `DecidableEq (Ciphertext params encoding)` — sidesteps
needing a `DecidableEq encoding.EncodedU`/`EncodedV` instance, which (like `++`) typeclass search
won't derive by unfolding `encoding`'s definition. -/
def decaps768 (dk : DecapsulationKey params encoding) (c : Ciphertext params encoding) :
    SharedSecret :=
  let m' := KPKE.decrypt ring encoding primitives dk.dkPKE c
  let (k', r') := primitives.gEncaps m' dk.ekHash
  let kBar := primitives.jReject dk.z c.uEncoded c.vEncoded
  let c' := KPKE.encrypt ring encoding primitives dk.ekPKE m' r'
  if uBytes c.uEncoded = uBytes c'.uEncoded ∧ vBytes c.vEncoded = vBytes c'.vEncoded then k'
  else kBar

/-! ## FIPS 203 §7.2/§7.3 input-validation checks

`keygen768`/`encaps768`/`decaps768` above are the *internal* algorithms (Algorithms 19-21) — they
never reject a malformed key, matching VCVio's own `keygenInternal`/`encapsInternal`/
`decapsInternal`. FIPS 203's top-level `ML-KEM.Encaps`/`ML-KEM.Decaps` additionally run one input
check each before calling into the internal algorithm; these are that check, exposed separately
rather than folded into `encaps768`/`decaps768` themselves so a caller can still reach the
internal algorithms directly (as `kemMLKEM768` does — see the module doc's discussion of `Reliable`,
which is about noise, not malformed keys; a real deployment would call these checks first). -/

/-- FIPS 203 §7.2's encapsulation-key modulus check: decoding `tHatEncoded` and re-encoding it must
reproduce the same bytes. Fails exactly when some coefficient in the encoded vector is not fully
reduced mod `q` — i.e. genuinely represents a modulus violation, not an implementation defect. -/
def checkEncapsulationKey (ek : EncapsulationKey params encoding) : Bool :=
  tBytes (encoding.byteEncode12Vec (encoding.byteDecode12Vec ek.tHatEncoded)) == tBytes ek.tHatEncoded

/-- FIPS 203 §7.3's decapsulation-key hash check: `dk.ekHash` must match a fresh
`H(ekPKE)` recomputation. -/
def checkDecapsulationKey (dk : DecapsulationKey params encoding) : Bool :=
  ofVector (primitives.hEncapsulationKey dk.ekPKE.tHatEncoded dk.ekPKE.rho) == ofVector dk.ekHash

/-! ## Size facts: `keygen768`/`encaps768`'s outputs are always well-formed -/

theorem keygen768_ek_wf (d z : Seed32) :
    (tBytes (keygen768 d z).1.tHatEncoded).size = 384 * params.k := by
  unfold keygen768 KPKE.keygenFromSeed
  dsimp only
  show (tBytes (encoding.byteEncode12Vec _)).size = 384 * params.k
  unfold tBytes
  show (encoding.byteEncode12Vec _ : ByteArray).size = 384 * params.k
  exact concreteEncoding_byteEncode12Vec_size params _

theorem keygen768_dk_wf (d z : Seed32) :
    (tBytes (keygen768 d z).2.dkPKE.sHatEncoded).size = 384 * params.k ∧
      (tBytes (keygen768 d z).2.ekPKE.tHatEncoded).size = 384 * params.k := by
  constructor
  · unfold keygen768 KPKE.keygenFromSeed
    dsimp only
    show (tBytes (encoding.byteEncode12Vec _)).size = 384 * params.k
    unfold tBytes
    show (encoding.byteEncode12Vec _ : ByteArray).size = 384 * params.k
    exact concreteEncoding_byteEncode12Vec_size params _
  · exact keygen768_ek_wf d z

private theorem encaps768_ct_wf (ek : EncapsulationKey params encoding) (m : Message) :
    (uBytes (encaps768 ek m).2.uEncoded).size = 32 * params.du * params.k ∧
      (vBytes (encaps768 ek m).2.vEncoded).size = 32 * params.dv := by
  unfold encaps768 KPKE.encrypt
  dsimp only
  refine ⟨?_, ?_⟩
  · show (encoding.byteEncodeDUVec _ : ByteArray).size = 32 * params.du * params.k
    exact concreteEncoding_byteEncodeDUVec_size params _
  · show (encoding.byteEncodeDV _ : ByteArray).size = 32 * params.dv
    exact concreteEncoding_byteEncodeDV_size params _

/-! ## `State`: an expandable stream from one 32-byte seed

`keygen768` alone needs 64 bytes (`d`, `z`); `encaps768` needs 32 more (`m`) — more than a single
32-byte value can supply directly. Mirrors `Sphinx.Interface.SeedStream`'s "counter + inexhaustible
stream" shape: seed a SHAKE-256-based expanding stream once, draw as many 32-byte blocks as
needed. -/

/-- The `i`-th 32-byte block derived from `seed`. -/
def seedBlock (seed : Vector UInt8 32) (i : Nat) : Vector UInt8 32 :=
  toVecN 32 (SLHDSA.Concrete.Keccak.shake256 (ofVector seed |>.push i.toUInt8) 32)

/-- Counter plus the original seed. -/
abbrev State := Nat × Vector UInt8 32

def nextDraw : EStateM KEMError State (Vector UInt8 32) :=
  fun (i, seed) => .ok (seedBlock seed i) (i + 1, seed)

def stateFromSeed (seed : Vector UInt8 32) : State := (0, seed)

/-! ## The `KEM.KEM` instance -/

/-- `s` is `Reliable` when the draw it would next produce, encapsulated against any keypair,
decapsulates back correctly — see the module doc for why this is stated operationally rather than
via a checkable noise bound. -/
def Reliable (s : State) : Prop :=
  ∀ (dk : DecapsulationKey params encoding) (ek : EncapsulationKey params encoding),
    ek = dk.ekPKE →
    decaps768 dk (encaps768 ek (seedBlock s.2 s.1)).2 = (encaps768 ek (seedBlock s.2 s.1)).1

def encapM (pk : PublicKey) : EStateM KEMError State (CT × Vector UInt8 32) := do
  let m ← nextDraw
  pure (⟨(encaps768 pk.1 m).2, encaps768_ct_wf pk.1 m⟩, (encaps768 pk.1 m).1)

def decapM (sk : PrivateKey) (c : CT) : EStateM KEMError State (Vector UInt8 32) :=
  pure (decaps768 sk.1 c.1)

def derivePublicKeyM (sk : PrivateKey) : PublicKey := ⟨sk.1.ekPKE, sk.2.2⟩

/-- `injection`/`congrArg Subtype.val`-style extraction from `hc` here hits a pathological
`maxRecDepth`/`whnf` blowup — the `CT` subtype's embedded well-formedness proof makes that
machinery expensive to elaborate. A single `simp only [...]` unfolding `encapM` and splitting the
`EStateM.Result`/`Prod` equality all at once avoids it entirely (confirmed: the `injection`-based
version times out even at `maxRecDepth 65536`; this version is immediate). -/
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

theorem decodePrivateKey_totalM (v : Vector UInt8 params.secretKeyBytes) :
    ∃ sk : PrivateKey, decodePrivateKey v = some sk := by
  unfold decodePrivateKey
  exact ⟨_, rfl⟩

def dummySeed : Seed32 := Vector.replicate 32 0

def dummyPk : PublicKey := ⟨(keygen768 dummySeed dummySeed).1, keygen768_ek_wf _ _⟩

def dummySk : PrivateKey := ⟨(keygen768 dummySeed dummySeed).2, keygen768_dk_wf _ _⟩

def dummyCt : CT := ⟨(encaps768 dummyPk.1 dummySeed).2, encaps768_ct_wf _ _⟩

/-- The assembled `KEM.KEM` instance for ML-KEM-768. -/
def kemMLKEM768 : KEM where
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

/-! ## A second instance, for wire compatibility with Go's `crypto/mlkem`

`kemMLKEM768`'s `PrivateKey` retains the FIPS 203 *expanded* key (`sHat`, `tHat`, `rho`, `ekHash`,
`z`) and serializes exactly that — the right choice for the standalone `"mlkem768-kem"` entry, and
what NIST's own ACVP vectors are stated in terms of. But `d` (`keygen768`'s other seed half) is
discarded once `dkPKE`/`ekPKE` are computed — it is nowhere in `PrivateKey`'s value — so this
format cannot round-trip through the *compact* seed-based encoding Go's standard-library
`crypto/mlkem` uses instead (`DecapsulationKey.Bytes()`: "the decapsulation key as a 64-byte seed
in the 'd ‖ z' form", re-expanded on every operation rather than cached). Cross-checking real
KEM-Sphinx packets against Go needs that compact format, since a packet's recorded private key is
literal wire bytes a real Go node would hold — hence this second instance, `kemMLKEM768Seed`,
whose `PrivateKey` is `(d, z)` directly and whose wire encoding is `ek ‖ d ‖ z` (`1184 + 64 = 1248`
bytes), matching Go exactly. Everything else (`PublicKey`, `Ciphertext`, `State`, `Reliable`) is
unchanged from `kemMLKEM768`; only the private-key type and everything that mentions it change. -/

abbrev SeedPrivateKey := Seed32 × Seed32

def derivePublicKeyFromSeed (sk : SeedPrivateKey) : PublicKey :=
  ⟨(keygen768 sk.1 sk.2).1, keygen768_ek_wf sk.1 sk.2⟩

/-- The full expanded decapsulation key `dk` this seed determines — recomputed on every call,
exactly as Go's `Decapsulate` recomputes it from the stored seed rather than caching it. -/
private def expandSeed (sk : SeedPrivateKey) : PrivateKey :=
  ⟨(keygen768 sk.1 sk.2).2, keygen768_dk_wf sk.1 sk.2⟩

def decapMFromSeed (sk : SeedPrivateKey) (c : CT) : EStateM KEMError State (Vector UInt8 32) :=
  decapM (expandSeed sk) c

theorem honestRoundTripFromSeed (sk : SeedPrivateKey) : ∀ s, Reliable s → ∀ c k s',
    encapM (derivePublicKeyFromSeed sk) s = .ok (c, k) s' → ∀ t, ∃ t', decapMFromSeed sk c t = .ok k t' :=
  honestRoundTripM (expandSeed sk)

def encodePrivateKeyFromSeed (sk : SeedPrivateKey) : Vector UInt8 (params.publicKeyBytes + 64) :=
  toVecN _
    (ofVector (encodePublicKey (derivePublicKeyFromSeed sk)) ++ (ofVector sk.1 ++ ofVector sk.2))

def decodePrivateKeyFromSeed (v : Vector UInt8 (params.publicKeyBytes + 64)) :
    Option SeedPrivateKey :=
  let b := ofVector v
  let rest := b.extract params.publicKeyBytes b.size
  some (toVecN 32 (rest.extract 0 32), toVecN 32 (rest.extract 32 rest.size))

theorem decodePrivateKeyFromSeed_total (v : Vector UInt8 (params.publicKeyBytes + 64)) :
    ∃ sk, decodePrivateKeyFromSeed v = some sk := ⟨_, rfl⟩

theorem decode_encode_privFromSeed (sk : SeedPrivateKey) :
    decodePrivateKeyFromSeed (encodePrivateKeyFromSeed sk) = some sk := by
  obtain ⟨d, z⟩ := sk
  unfold encodePrivateKeyFromSeed decodePrivateKeyFromSeed
  dsimp only
  generalize hekdef : ofVector (encodePublicKey (derivePublicKeyFromSeed (d, z))) = ek
  have hek : ek.size = params.publicKeyBytes := by rw [← hekdef]; exact size_ofVector _
  have hd : (ofVector d).size = 32 := size_ofVector _
  have hz : (ofVector z).size = 32 := size_ofVector _
  have hsize : (ek ++ (ofVector d ++ ofVector z)).size = params.publicKeyBytes + 64 := by
    rw [ByteArray.size_append, ByteArray.size_append, hek, hd, hz]
  rw [ofVector_toVecN _ hsize]
  have hrest : (ek ++ (ofVector d ++ ofVector z)).extract params.publicKeyBytes
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

/-- The assembled `KEM.KEM` instance for ML-KEM-768, wire-compatible with Go's `crypto/mlkem`. -/
def kemMLKEM768Seed : KEM where
  State := State
  PublicKey := PublicKey
  PrivateKey := SeedPrivateKey
  Ciphertext := CT
  Plaintext := Vector UInt8 32

  pubI := ⟨dummyPk⟩
  privI := ⟨(dummySeed, dummySeed)⟩
  ctI := ⟨dummyCt⟩
  ptI := ⟨Vector.replicate 32 0⟩
  stateI := ⟨(0, dummySeed)⟩

  publicKeySize := params.publicKeyBytes
  privateKeySize := params.publicKeyBytes + 64
  ciphertextSize := params.ciphertextBytes
  plaintextSize := 32

  encodePublicKey := encodePublicKey
  decodePublicKey := decodePublicKey
  encodePrivateKey := encodePrivateKeyFromSeed
  decodePrivateKey := decodePrivateKeyFromSeed
  encodeCiphertext := encodeCiphertext
  decodeCiphertext := decodeCiphertext
  encodePlaintext := id

  decap := decapMFromSeed
  encap := encapM
  Reliable := Reliable
  generate := do
    let d ← nextDraw
    let z ← nextDraw
    pure ⟨derivePublicKeyFromSeed (d, z), (d, z), honestRoundTripFromSeed (d, z)⟩
  stateFromSeed := stateFromSeed
  derivePublicKey := derivePublicKeyFromSeed
  honestRoundTrip := honestRoundTripFromSeed
  decodePrivateKey_total := decodePrivateKeyFromSeed_total

  decode_encode_pub := decode_encode_pub
  decode_encode_priv := decode_encode_privFromSeed
  decode_encode_ct := decode_encode_ct

  plaintextEq := inferInstance

end CryptWalker.KEM.MLKEM768
