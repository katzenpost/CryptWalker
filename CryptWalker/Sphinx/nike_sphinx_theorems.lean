/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.commands
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.sphinx
import CryptWalker.Sphinx.common
import CryptWalker.Sphinx.surb
import CryptWalker.Sphinx.kdf
import CryptWalker.Cipher.ChaCha20
import CryptWalker.WideBlockCipher.WideBlockCipher
import CryptWalker.WideBlockCipher.AEZ
import CryptWalker.MAC.MAC
import CryptWalker.KDF.KDF
import CryptWalker.KDF.HKDF
import CryptWalker.StreamCipher.StreamCipher
import CryptWalker.StreamCipher.AES256CTR
import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.Schemes
import CryptWalker.Sphinx.wrap_resistance
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes
import CryptWalker.Sphinx.nike_sphinx

namespace CryptWalker.Sphinx.NIKESphinx

open OracleComp OracleSpec ENNReal
open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.KDF (PacketKeys)
open CryptWalker.Cipher.ChaCha20 (keystream32)
open CryptWalker.WideBlockCipher (WideBlockCipher)
open CryptWalker.MAC (MAC)
open CryptWalker.KDF (KDF)
open CryptWalker.StreamCipher (StreamCipher)
open CryptWalker.NIKE.NIKE (NIKE telescopeElem telescopeSecret telescope_agree)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)

/-! # NIKE-Sphinx

Port of `sphinx.go`'s NIKE path (`createHeader`, `newNIKEPacket`, `unwrapNIKE`), genuinely generic
over *any* `NIKE` (`CryptWalker/NIKE/NIKE.lean`) — not hardcoded to X25519, and not bundled with a
proof of any particular key size either. A `NIKE` already carries its own
`publicKeySize`/`privateKeySize`/`sharedSecretSize`; every function below just reads those fields
off the `nike : NIKE` it's given and sizes its `Vector`s accordingly (`Common.toVecN`), the same
way `Geometry.ofNIKE`/`buildNIKE` already compute `headerLength` from `scheme.publicKeySize` rather
than assuming 32. `createHeader` takes its randomness (client ephemeral key, hop-count-hiding
filler) as plain arguments rather than `IO`, so it stays pure.

The one place a fixed width still appears is `blindingFactorPrivKey`: matching Go's
`rand.NewDeterministicRandReader`, it reads exactly one 32-byte ChaCha20 block regardless of
`nike.privateKeySize` — a real limitation for a hypothetical NIKE with a >32-byte private key
(silently zero-padded, since it's built from `Common.toVecN`), stated here rather than hidden. It
does not affect any NIKE currently registered.

`unwrapNIKE` needs no randomness, which is what makes it the half `Crypto.aez_test` and friends
can eventually check against Go's own `sphinx_vectors.json` byte-for-byte: that file's packets
were built with a client ephemeral key it doesn't record, so `createHeader`'s output can't be
reproduced from it, but `Unwrap` is deterministic. -/

private theorem nikeEncodePublicKey_injective (nike : NIKE) :
    Function.Injective nike.encodePublicKey := fun a b h => by
  have := congrArg nike.decodePublicKey h
  rwa [nike.decode_encode_pub, nike.decode_encode_pub, Option.some.injEq] at this

private theorem nikeEncodePrivateKey_injective (nike : NIKE) :
    Function.Injective nike.encodePrivateKey := fun a b h => by
  have := congrArg nike.decodePrivateKey h
  rwa [nike.decode_encode_priv, nike.decode_encode_priv, Option.some.injEq] at this

instance (nike : NIKE) : DecidableEq nike.PublicKey := fun a b =>
  decidable_of_iff (nike.encodePublicKey a = nike.encodePublicKey b)
    ⟨fun h => nikeEncodePublicKey_injective nike h, fun h => h ▸ rfl⟩

noncomputable instance (nike : NIKE) : Fintype nike.PrivateKey :=
  Fintype.ofInjective nike.encodePrivateKey (nikeEncodePrivateKey_injective nike)

instance (nike : NIKE) : DecidableEq nike.PrivateKey := fun a b =>
  decidable_of_iff (nike.encodePrivateKey a = nike.encodePrivateKey b)
    ⟨fun h => nikeEncodePrivateKey_injective nike h, fun h => h ▸ rfl⟩

instance (nike : NIKE) : Inhabited nike.PrivateKey :=
  ⟨nike.privateKeyFromSeed (Vector.replicate 32 0)⟩

instance (nike : NIKE) : Inhabited nike.PublicKey := ⟨nike.derivePublicKey default⟩

noncomputable instance (nike : NIKE) : SampleableType nike.PrivateKey := SampleableType.ofFintype _

/-- Decode a `PrivateKey`'s raw bytes — the one place a caller-supplied value that turns out not
to encode a valid key gets rejected, rather than silently misused. `toVecN` never fails (it pads
or truncates), so the rejection comes entirely from `nike.decodePrivateKey`'s own canonical-encoding
check. -/
private def nikeDecodePrivateKey (nike : NIKE) (bytes : ByteArray) : Except String nike.PrivateKey :=
  match nike.decodePrivateKey (toVecN nike.privateKeySize bytes) with
  | none => throw "sphinx: invalid private key encoding"
  | some sk => pure sk

/-- The group action, at the byte level: decode `pkBytes`, check it's safe to act on (`NIKE.Safe`
— rejecting e.g. small-order Curve25519 points), then run `groupAction` and re-encode the result.
Both failure paths (bad encoding, unsafe key) are genuine, checked ones — nothing here silently
processes whatever bytes a packet carried. -/
private def nikeDH (nike : NIKE) (sk : nike.PrivateKey) (pkBytes : ByteArray) :
    Except String ByteArray :=
  match nike.decodePublicKey (toVecN nike.publicKeySize pkBytes) with
  | none => throw "sphinx: invalid public key encoding"
  | some pk =>
    if h : nike.Safe pk then pure (ofVector (nike.encodeSharedSecret (nike.groupAction sk pk h)))
    else throw "sphinx: unsafe public key"

/-- Re-blind an envelope by a factor, at the byte level — `nikeDH` with the factor as private key
and the envelope as public key. Total, falling back to `pk` unchanged on decode/safety failure
(provably unreachable in practice: every call site already established safety via a preceding
`nikeDH`). Resized to `pk.size` regardless of `nike.sharedSecretSize` (`size_nikeBlind` below),
so `createHeader`'s blinding chain preserves the group-element width with no size-agreement
proof needed. -/
private def nikeBlind (nike : NIKE) (pk factor : ByteArray) : ByteArray :=
  let result := match nike.decodePrivateKey (toVecN nike.privateKeySize factor) with
    | none => pk
    | some sk => (nikeDH nike sk pk).toOption.getD pk
  ofVector (toVecN pk.size result)

@[simp] lemma size_nikeBlind (nike : NIKE) (pk factor : ByteArray) :
    (nikeBlind nike pk factor).size = pk.size := by
  unfold nikeBlind
  exact Util.Bytes.size_ofVector _

/-- **`nikeDH`, bridged to the typed group action**: given an honestly-encoded, `Safe` public key,
`nikeDH` computes exactly `groupAction sk pk h`, re-encoded. The byte-level `decodePublicKey`
round trip is `decode_encode_pub`; nothing else in `nikeDH`'s definition depends on the caller's
bytes once they decode to `pk`. The atomic byte-level fact `NIKE.telescope_agree`'s abstract
argument needs threaded through `createHeader`/`unwrapNIKE`'s actual `ByteArray` calls. -/
theorem nikeDH_bridge (nike : NIKE) (sk : nike.PrivateKey) (pk : nike.PublicKey)
    (h : nike.Safe pk) :
    nikeDH nike sk (ofVector (nike.encodePublicKey pk))
      = .ok (ofVector (nike.encodeSharedSecret (nike.groupAction sk pk h))) := by
  unfold nikeDH
  rw [toVecN_ofVector, nike.decode_encode_pub]
  dsimp only
  rw [dif_pos h]
  rfl

/-- **`nikeBlind`, bridged to the typed re-blinding action**: given an honestly-encoded, `Safe`
envelope and any factor bytes that decode to `sk` (not necessarily `sk`'s canonical encoding —
`createHeader`'s actual blinding factors are raw `blindingFactorPrivKey` output, never
re-encoded), `nikeBlind` computes exactly `reinterpret (groupAction sk pk h)`, re-encoded, via
`NIKE.encodePublicKey_reinterpret` once `nikeDH_bridge` identifies the DH output. -/
theorem nikeBlind_bridge (nike : NIKE) (pk : nike.PublicKey) (sk : nike.PrivateKey)
    (h : nike.Safe pk) (factor : ByteArray)
    (hfactor : nike.decodePrivateKey (toVecN nike.privateKeySize factor) = some sk) :
    nikeBlind nike (ofVector (nike.encodePublicKey pk)) factor
      = ofVector (nike.encodePublicKey (nike.reinterpret (nike.groupAction sk pk h))) := by
  unfold nikeBlind
  rw [hfactor]
  dsimp only
  rw [nikeDH_bridge nike sk pk h]
  dsimp only [Except.toOption, Option.getD]
  rw [Util.Bytes.size_ofVector, ← nike.encodePublicKey_reinterpret]
  exact ofVector_toVecN _ (Util.Bytes.size_ofVector _)

/-- As `nikeBlind`, but on decoded `NIKE` values rather than raw bytes — what
`NIKESphinxScheme.blind` (the abstract re-blindable-envelope interface `wrap_resistant` is stated
against) actually needs. -/
private def nikeBlindTyped (nike : NIKE) (factor : nike.PrivateKey) (pk : nike.PublicKey) :
    nike.PublicKey :=
  if h : nike.Safe pk then
    (nike.decodePublicKey
      (toVecN nike.publicKeySize (ofVector (nike.encodeSharedSecret (nike.groupAction factor pk h))))
    ).getD pk
  else pk

/-- A client's own public key, from its private key's raw bytes — total, falling back to the
private-key bytes themselves if they fail to decode (unreachable whenever a caller like
`createHeader` already succeeded, since it decodes the same bytes with the same function first). -/
private def nikeSelfPublicKeyBytes (nike : NIKE) (skBytes : ByteArray) : ByteArray :=
  match nike.decodePrivateKey (toVecN nike.privateKeySize skBytes) with
  | none => skBytes
  | some sk => ofVector (nike.encodePublicKey (nike.derivePublicKey sk))

/-- `BlindingFactor`'s raw seed, as the NIKE private key it represents: the first 32 bytes of
`rand.NewDeterministicRandReader(seed)`, unclamped (clamping, if any, happens inside
`nike.decodePrivateKey`/`groupAction`, matching `nike/x25519.NewKeypair`). Always exactly 32
bytes — see this file's module doc for the resulting limitation on `nike.privateKeySize > 32`. -/
private def blindingFactorPrivKey (seed : Vector UInt8 32) : ByteArray := ⟨keystream32 seed.toArray⟩

/-- Everything `crypto.KDF` derives for one hop. `blindingFactor` is raw bytes, not a decoded
`nike.PrivateKey`, since `HopKeys` is shared with `KEMSphinx` (unused there) and isn't itself
parametric in which `NIKE` produced it. -/
structure HopKeys where
  headerMAC : Vector UInt8 32
  headerEncryption : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption : Vector UInt8 48
  blindingFactor : ByteArray
  deriving Inhabited

/-- `sharedSecret` is whatever a NIKE's `encodeSharedSecret` produced (no fixed width assumed).
Generic in `kdfS` via `Sphinx.KDF.packetKeysFrom`, agreeing with `Sphinx.KDF.sphinxKDF`
definitionally when `kdfS = CryptWalker.KDF.HKDF.hkdfSha256Expand`. Shared with
`kem_sphinx_theorems.lean`. -/
def deriveHopKeys (kdfS : KDF) (sharedSecret : ByteArray) : HopKeys :=
  let pk : PacketKeys := CryptWalker.Sphinx.KDF.packetKeysFrom kdfS sharedSecret
  { headerMAC := pk.headerMAC
    headerEncryption := pk.headerEncryption
    headerEncryptionIV := pk.headerEncryptionIV
    payloadEncryption := pk.payloadEncryption
    blindingFactor := blindingFactorPrivKey pk.blindingFactorSeed }

/-- **`createHeader`**. `filler` must be exactly `(geom.nrHops - path.size) *
geom.perHopRoutingInfoLength` bytes (ignored, and may be empty, when `path.size = geom.nrHops`)
— the random padding that hides a shorter-than-maximum path's true hop count. -/
def createHeader (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) : Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  let clientSk ← nikeDecodePrivateKey nike clientPrivateKey
  let clientPublicKey0 := ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk))

  -- Per-hop shared secrets/keys, and the (progressively blinded) group elements.
  let mut groupElements : Array ByteArray := Array.replicate nrHops clientPublicKey0
  let mut keys : Array HopKeys := #[deriveHopKeys kdfS (← nikeDH nike clientSk (path[0]!).publicKey)]
  let mut clientPublicKey := clientPublicKey0
  for i in [1:nrHops] do
    let mut sharedSecret ← nikeDH nike clientSk (path[i]!).publicKey
    for j in [0:i] do
      let fj ← nikeDecodePrivateKey nike (keys[j]!).blindingFactor
      sharedSecret ← nikeDH nike fj sharedSecret
    keys := keys.push (deriveHopKeys kdfS sharedSecret)
    clientPublicKey := nikeBlind nike clientPublicKey (keys[i-1]!).blindingFactor
    groupElements := groupElements.set! i clientPublicKey

  -- Per-hop routing-info keystream and encrypted padding.
  let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
  let mut riKeyStream : Array ByteArray := #[]
  let mut riPadding : Array ByteArray := #[]
  for i in [0:nrHops] do
    let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
      (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
    let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
    let mut thisPad := ks.extract ksLen totalRiLen
    if i > 0 then
      let prevPad := riPadding[i - 1]!
      thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
        ++ thisPad.extract prevPad.size thisPad.size
    riKeyStream := riKeyStream.push (ks.extract 0 ksLen)
    riPadding := riPadding.push thisPad

  -- Assemble the routing_information block, back to front.
  let mut routingInfo : ByteArray := if geom.nrHops > nrHops then filler else ByteArray.empty
  let mut macBytes : ByteArray := ByteArray.empty
  for iRev in [0:nrHops] do
    let i := nrHops - 1 - iRev
    let isTerminal := i == nrHops - 1
    let hop := path[i]!
    let budget := if isTerminal then geom.perHopRoutingInfoLength
      else geom.perHopRoutingInfoLength - geom.nextNodeHopLength
    let mut riFragment ← commandsToBytes budget hop.commands
    if !isTerminal then
      let next := path[i + 1]!
      riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
    routingInfo := zeroPadTo geom.perHopRoutingInfoLength riFragment ++ routingInfo
    routingInfo := xorBytes routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ groupElements[i]! ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)

  let hdr := v0AD ++ groupElements[0]! ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

private theorem ite_pure_yield {α : Type} (c : Prop) [Decidable c] (a b : α) :
    (if c then (pure (ForInStep.yield a) : Except String (ForInStep α)) else pure (ForInStep.yield b)) =
      pure (ForInStep.yield (if c then a else b)) := by
  split <;> rfl

@[simp] private theorem byteArray_empty_size : (ByteArray.empty : ByteArray).size = 0 := rfl

@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

/-- As `Common.Array.getElem!_stable_of_pushes`, for a trace whose array size is `j + 1` rather
than `j` at step `j` — `createHeader`'s own `keys` trace: it starts at *one* entry (the first
hop's key, already known before the loop over `[1:nrHops]` even begins), not zero. -/
private theorem Array.getElem!_stable_of_pushes' {α : Type} [Inhabited α] (t : Nat → Array α) (n : Nat)
    (hpush : ∀ j, j < n → ∃ x, t (j + 1) = (t j).push x) (hsize : ∀ j, j ≤ n → (t j).size = j + 1) :
    ∀ i m, i < m → m ≤ n → (t m)[i]! = (t (i + 1))[i]! := by
  intro i m him hmn
  induction m with
  | zero => omega
  | succ m ih =>
    rcases Nat.lt_or_ge i m with h | h
    · obtain ⟨x, hx⟩ := hpush m (by omega)
      rw [hx, CryptWalker.Sphinx.Common.Array.getElem!_push_stable _ _ _
        (by rw [hsize m (by omega)]; omega), ih h (by omega)]
    · have hie : i = m := by omega
      rw [hie]

/-- As `Array.getElem!_stable_of_pushes'`, collapsed to compare against the array's value at the
index's own step `i` directly (rather than one step later) — one more `getElem!_push_stable`
closes that last gap. -/
private theorem Array.getElem!_stable_from_pushes {α : Type} [Inhabited α] (t : Nat → Array α) (n : Nat)
    (hpush : ∀ j, j < n → ∃ x, t (j + 1) = (t j).push x) (hsize : ∀ j, j ≤ n → (t j).size = j + 1) :
    ∀ i m, i ≤ m → m ≤ n → (t m)[i]! = (t i)[i]! := by
  intro i m him hmn
  rcases eq_or_lt_of_le him with heq | hlt
  · rw [heq]
  · rw [Array.getElem!_stable_of_pushes' t n hpush hsize i m hlt hmn]
    obtain ⟨x, hx⟩ := hpush i (by omega)
    rw [hx, CryptWalker.Sphinx.Common.Array.getElem!_push_stable _ _ _
      (by rw [hsize i (by omega)]; omega)]

/-- **The inner "keep DH-ing" loop, bridged**: given an honestly-encoded `Safe` target public key
and a sequence of `n` already-honestly-decodable factor bytes, running `nikeDH` once against the
target then `n` more times against each factor in turn (`createHeader`'s inner loop, exactly)
reproduces `NIKE.telescopeSecret`'s value at `n`. Pure induction on `n` using `nikeDH_bridge` at
each step — no new algebra beyond what that lemma already gives. -/
private theorem nikeDH_innerLoop_bridge (nike : NIKE) (baseSk targetSk : nike.PrivateKey)
    (pkBytes : ByteArray) (hpk : pkBytes = ofVector (nike.encodePublicKey (nike.derivePublicKey targetSk)))
    (factorBytes : Nat → ByteArray) (f : Nat → nike.PrivateKey) (n : Nat)
    (hf : ∀ k, k < n → nike.decodePrivateKey (toVecN nike.privateKeySize (factorBytes k)) = some (f k))
    (ss0 finalSS : ByteArray)
    (hss0 : nikeDH nike baseSk pkBytes = Except.ok ss0)
    (hfinal : forIn (List.range' 0 n) ss0 (fun k acc => do
        let fj ← nikeDecodePrivateKey nike (factorBytes k)
        ForInStep.yield <$> nikeDH nike fj acc) = Except.ok finalSS) :
    finalSS = ofVector (nike.encodeSharedSecret (telescopeSecret nike baseSk targetSk f n).1) := by
  have hss0' : ss0 = ofVector (nike.encodeSharedSecret (telescopeSecret nike baseSk targetSk f 0).1) := by
    rw [hpk] at hss0
    rw [nikeDH_bridge nike baseSk (nike.derivePublicKey targetSk) (nike.derive_safe targetSk)] at hss0
    injection hss0 with hss0
    exact hss0.symm
  obtain ⟨t, ht0, htn, htstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace _ _
    (by
      intro k a a' hk hgb
      obtain ⟨fj, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
      obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
      exact absurd hgb (by simp))
    _ _ hfinal
  have hlen : (List.range' 0 n).length = n := by simp
  rw [hlen] at htn
  have main : ∀ k (hk : k ≤ n), t k = ofVector (nike.encodeSharedSecret (telescopeSecret nike baseSk targetSk f k).1) := by
    intro k
    induction k with
    | zero => intro _; rw [ht0]; exact hss0'
    | succ k ih =>
      intro hk
      have hk' : k < n := by omega
      have hkl : k < (List.range' 0 n).length := by rw [hlen]; exact hk'
      have hstep := htstep k hkl
      rw [List.getElem_range'_1 k hkl, Nat.zero_add] at hstep
      obtain ⟨fj, hfj, hstep⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hstep
      obtain ⟨y', hy', hstep⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hstep
      injection hstep with stepEq
      have hfjeq0 : nike.decodePrivateKey (toVecN nike.privateKeySize (factorBytes k)) = some fj := by
        unfold nikeDecodePrivateKey at hfj
        match hd : nike.decodePrivateKey (toVecN nike.privateKeySize (factorBytes k)), hfj with
        | none, hfj => injection hfj
        | some sk, hfj =>
          simp only [pure, Except.pure, Except.ok.injEq] at hfj
          exact congrArg some hfj
      have hfjeq : fj = f k := by
        rw [hf k hk'] at hfjeq0; injection hfjeq0 with hfjeq0; exact hfjeq0.symm
      have hik := ih (by omega)
      rw [hfjeq, hik, ← nike.encodePublicKey_reinterpret] at hy'
      rw [nikeDH_bridge nike (f k) (nike.reinterpret (telescopeSecret nike baseSk targetSk f k).1)
        (telescopeSecret nike baseSk targetSk f k).2] at hy'
      injection hy' with hy'
      rw [← stepEq, ← hy']
      rfl
  have hmain := main n (le_refl n)
  rw [htn] at hmain
  exact hmain

/-- `a.push x`'s new element, addressed via `!` at the array's own (pre-push) size — the
`getElem!` counterpart of `Array.getElem_push_eq`. -/
private theorem getElem!_push_eq {α : Type} [Inhabited α] (a : Array α) (x : α) :
    (a.push x)[a.size]! = x := by
  rw [getElem!_pos (a.push x) a.size (by rw [Array.size_push]; omega), Array.getElem_push_eq]

/-- As `getElem!_push_eq`, addressed by an arbitrary index already known to equal the array's
size — avoids rewriting `i` in place at the call site, which would also hit `i`'s other
occurrences inside the pushed value itself. -/
private theorem getElem!_push_eq' {α : Type} [Inhabited α] (a : Array α) (x : α) (i : Nat)
    (hi : i = a.size) : (a.push x)[i]! = x := by
  rw [hi]; exact getElem!_push_eq a x

/-- **`createHeader`'s second loop, at the content level — kept in its native `forIn`/`Except`
shape**: `riKeyStream[i]!`/`riPadding[i]!` spelled out exactly, matching what `createHeader`'s
actual elaborated body produces. Mirrors `createKEMHeader_loop2_content`. -/
private theorem createHeader_loop2_content_native (streamS : StreamCipher) (geom : Geometry)
    (keys : Array HopKeys) (nrHops : Nat) (final : Array ByteArray × Array ByteArray)
    (hfinal : forIn (List.range' 0 nrHops) (#[], #[])
        (fun i (st : Array ByteArray × Array ByteArray) =>
          (pure (ForInStep.yield
            (let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
              (ofVector (keys[i]!).headerEncryptionIV)
              (geom.routingInfoLength + geom.perHopRoutingInfoLength)
             let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
              - (i + 1) * geom.perHopRoutingInfoLength
             let thisPad0 := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
             if i > 0 then
               (st.1.push (ks.extract 0 ksLen), st.2.push
                 (xorBytes (thisPad0.extract 0 st.2[i - 1]!.size) st.2[i - 1]!
                   ++ thisPad0.extract st.2[i - 1]!.size thisPad0.size))
             else (st.1.push (ks.extract 0 ksLen), st.2.push thisPad0))) :
              Except String (ForInStep (Array ByteArray × Array ByteArray)))) = Except.ok final)
    (i : Nat) (hi : i < nrHops) :
    final.1[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
        (ofVector (keys[i]!).headerEncryptionIV)
        (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
      ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (i + 1) * geom.perHopRoutingInfoLength)
    ∧ final.2[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 final.2[i - 1]!.size) final.2[i - 1]!
           ++ thisPad0.extract final.2[i - 1]!.size thisPad0.size
       else thisPad0) := by
  have hnd : ∀ (b : Nat) (a a' : Array ByteArray × Array ByteArray), b ∈ List.range' 0 nrHops →
      (fun i (st : Array ByteArray × Array ByteArray) =>
        (pure (ForInStep.yield
          (let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)
           let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength
           let thisPad0 := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
           if i > 0 then
             (st.1.push (ks.extract 0 ksLen), st.2.push
               (xorBytes (thisPad0.extract 0 st.2[i - 1]!.size) st.2[i - 1]!
                 ++ thisPad0.extract st.2[i - 1]!.size thisPad0.size))
           else (st.1.push (ks.extract 0 ksLen), st.2.push thisPad0))) :
            Except String (ForInStep (Array ByteArray × Array ByteArray)))) b a
        ≠ Except.ok (ForInStep.done a') := by
    intro b a a' _hb hcontra
    simp only [pure, Except.pure, Except.ok.injEq] at hcontra
    split at hcontra <;> injection hcontra
  obtain ⟨s, hs0, hsl, hstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
    (List.range' 0 nrHops) _ hnd (#[], #[]) final hfinal
  have hlen : (List.range' 0 nrHops).length = nrHops := by simp
  have hsl' : s nrHops = final := by rw [← hlen]; exact hsl
  have hstep' : ∀ j, j < nrHops →
      (pure (ForInStep.yield
        (let ks := streamS.keystream (ofVector (keys[j]!).headerEncryption)
          (ofVector (keys[j]!).headerEncryptionIV)
          (geom.routingInfoLength + geom.perHopRoutingInfoLength)
         let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
          - (j + 1) * geom.perHopRoutingInfoLength
         let thisPad0 := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
         if j > 0 then
           ((s j).1.push (ks.extract 0 ksLen), (s j).2.push
             (xorBytes (thisPad0.extract 0 (s j).2[j - 1]!.size) (s j).2[j - 1]!
               ++ thisPad0.extract (s j).2[j - 1]!.size thisPad0.size))
         else ((s j).1.push (ks.extract 0 ksLen), (s j).2.push thisPad0))) :
          Except String (ForInStep (Array ByteArray × Array ByteArray)))
        = Except.ok (ForInStep.yield (s (j + 1))) := by
    intro j hj
    have := hstep j (by rw [hlen]; exact hj)
    simpa only [List.getElem_range', Nat.one_mul, Nat.zero_add] using this
  have hsize : ∀ j (hj : j ≤ nrHops), (s j).1.size = j ∧ (s j).2.size = j := by
    intro j hj
    induction j with
    | zero => simp [hs0]
    | succ j ih =>
      obtain ⟨ih1, ih2⟩ := ih (by omega)
      have hstepj := hstep' j (by omega)
      split at hstepj <;>
        · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
          rw [← hstepj]; simp [ih1, ih2]
  have hstable1 := Array.getElem!_stable_of_pushes (fun j => (s j).1) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      split at hstepj <;>
        · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
          exact ⟨_, (congrArg Prod.fst hstepj).symm⟩)
    (fun j hj => (hsize j hj).1)
  have hstable2 := Array.getElem!_stable_of_pushes (fun j => (s j).2) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      split at hstepj <;>
        · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
          exact ⟨_, (congrArg Prod.snd hstepj).symm⟩)
    (fun j hj => (hsize j hj).2)
  have h1 : final.1[i]! = (s (i + 1)).1[i]! := by
    rw [← hsl']; exact hstable1 i nrHops hi (le_refl _)
  have h2 : final.2[i]! = (s (i + 1)).2[i]! := by
    rw [← hsl']; exact hstable2 i nrHops hi (le_refl _)
  have hpi1 : (s i).1.size = i := (hsize i (by omega)).1
  have hpi2 : (s i).2.size = i := (hsize i (by omega)).2
  have hstepi := hstep' i hi
  split at hstepi
  · next hi0 =>
    simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepi
    have hfp : final.2[i - 1]! = (s i).2[i - 1]! := by
      rw [← hsl']
      have := hstable2 (i - 1) nrHops (by omega) (by omega)
      rwa [show i - 1 + 1 = i from by omega] at this
    refine ⟨?_, ?_⟩
    · rw [h1, ← congrArg Prod.fst hstepi, getElem!_push_eq' _ _ _ hpi1.symm]
    · dsimp only
      rw [if_pos hi0, h2, ← congrArg Prod.snd hstepi, getElem!_push_eq' _ _ _ hpi2.symm, ← hfp]
  · next hi0 =>
    simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepi
    refine ⟨?_, ?_⟩
    · rw [h1, ← congrArg Prod.fst hstepi, getElem!_push_eq' _ _ _ hpi1.symm]
    · dsimp only
      rw [if_neg hi0, h2, ← congrArg Prod.snd hstepi, getElem!_push_eq' _ _ _ hpi2.symm]

/-- **`riPadding[i]!`'s byte size**: exactly `(i+1) * perHopRoutingInfoLength`, by induction on
the content facts `createHeader_loop2_content_native`/`createHeader_unfold` produce. Needed for
`hopPacket`'s overall size, since `riPadding[k-1]!` is one of its components. -/
private theorem createHeader_loop2_padsize_of_content (streamS : StreamCipher) (geom : Geometry)
    (keys : Array HopKeys) (nrHops : Nat) (riKeyStream riPadding : Array ByteArray)
    (hriContent : ∀ i (_hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength) ∧
        riPadding[i]! =
          (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
           let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
             (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
           let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
           let thisPad0 := ks.extract ksLen totalRiLen
           if i > 0 then
             xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
               ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
           else thisPad0))
    (hle : ∀ i (_hi : i < nrHops),
        (i + 1) * geom.perHopRoutingInfoLength ≤ geom.routingInfoLength + geom.perHopRoutingInfoLength) :
    ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength := by
  intro i hi
  induction i with
  | zero =>
    obtain ⟨-, hval⟩ := hriContent 0 hi
    rw [hval]
    dsimp only
    rw [if_neg (by omega), ByteArray.size_extract, streamS.keystream_size]
    omega
  | succ i ih =>
    obtain ⟨-, hval⟩ := hriContent (i + 1) hi
    rw [hval]
    dsimp only
    rw [if_pos (by omega : i + 1 > 0)]
    have hihsize := ih (by omega)
    have hthis0size : ((streamS.keystream (ofVector (keys[i + 1]!).headerEncryption)
        (ofVector (keys[i + 1]!).headerEncryptionIV)
        (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract
        (geom.routingInfoLength + geom.perHopRoutingInfoLength
          - (i + 1 + 1) * geom.perHopRoutingInfoLength)
        (geom.routingInfoLength + geom.perHopRoutingInfoLength)).size
        = (i + 1 + 1) * geom.perHopRoutingInfoLength := by
      rw [ByteArray.size_extract, streamS.keystream_size]
      have := hle (i + 1) hi
      omega
    simp only [ByteArray.size_append, size_xorBytes, ByteArray.size_extract, Nat.add_sub_cancel] at *
    omega

set_option maxHeartbeats 1000000 in
/-- `createHeader`'s header always starts with `v0AD ++ groupElements[0]!`, and
`groupElements[0]!` is `clientPublicKey0` untouched — the blinding loop only ever writes indices
`≥ 1` of an array every entry of which starts as `clientPublicKey0`. Note the group-element slot's
width is `nike.publicKeySize`, not a fixed literal — genuinely different NIKEs get genuinely
different-width headers, matching `Geometry.buildNIKE`. -/
private theorem createHeader_hdr_bytesPub (nike : NIKE) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry)
    (clientPrivateKey : ByteArray) (filler : ByteArray) (path : Array PathHop)
    (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (h : createHeader nike macS kdfS streamS geom clientPrivateKey filler path = .ok (hdr, sprpKeys)) :
    hdr.extract 2 (2 + nike.publicKeySize) = nikeSelfPublicKeyBytes nike clientPrivateKey ∧
      2 + nike.publicKeySize ≤ hdr.size := by
  unfold createHeader at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error "sphinx: invalid path" : Except String (ByteArray × Array SPRPKey)) =
        Except.ok (hdr, sprpKeys) := h
    injection h'
  case isFalse =>
    split at h
    case isTrue =>
      have h' : (Except.error "sphinx: invalid filler length" : Except String (ByteArray × Array SPRPKey)) =
          Except.ok (hdr, sprpKeys) := h
      injection h'
    case isFalse =>
      rename_i h1 h2
      simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl,
        ite_pure_yield, pure_bind, bind_pure_comp] at h
      obtain ⟨clientSk, hSk, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨hop0, hHop0, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨loop1Final, hLoop1, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨y, -, hy⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok h
      have hhdr := congrArg Prod.fst hy
      simp only at hhdr
      have hidx0 : loop1Final.1[0]! =
          (Array.replicate path.size (ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)))
            : Array ByteArray)[0]! :=
        CryptWalker.Sphinx.Common.List.forIn_congr_of_forall_mem _ _
          (fun (st : Array ByteArray × Array HopKeys × ByteArray) => st.1[0]!)
          (by
            intro a a' i hi hgb
            obtain ⟨ss, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
            injection hgb with hgb
            rw [← hgb]
            exact Array.getElem!_set!_ne a.1 i 0 _ (by obtain ⟨j, -, rfl⟩ := List.mem_range'.mp hi; omega))
          (by
            intro a a' i hi hgb
            obtain ⟨ss, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
            exact absurd hgb (by simp))
          _ _ hLoop1
      have hpos : 0 < path.size := by
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        omega
      rw [hidx0, getElem!_pos _ _ (by simpa using hpos), Array.getElem_replicate] at hhdr
      have hv0 : v0AD.size = 2 := rfl
      have hpub : (ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk))).size
          = nike.publicKeySize := Util.Bytes.size_ofVector _
      have hself : nikeSelfPublicKeyBytes nike clientPrivateKey =
          ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)) := by
        have hSk' : nike.decodePrivateKey (toVecN nike.privateKeySize clientPrivateKey) = some clientSk := by
          unfold nikeDecodePrivateKey at hSk
          match hd : nike.decodePrivateKey (toVecN nike.privateKeySize clientPrivateKey), hSk with
          | none, hSk => injection hSk
          | some sk, hSk =>
            simp only [pure, Except.pure, Except.ok.injEq] at hSk
            exact congrArg some hSk
        unfold nikeSelfPublicKeyBytes
        rw [hSk']
      rw [hself]
      refine ⟨?_, by simp [← hhdr, hv0, hpub]; omega⟩
      rw [← hhdr, CryptWalker.Util.Bytes.extract_append_of_le _ _ (by simp [hv0]),
        CryptWalker.Util.Bytes.extract_append_of_le _ _ (by simp [hv0, hpub])]
      simpa [hv0, hpub] using CryptWalker.Util.Bytes.extract_append_right v0AD
        (ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)))

set_option maxHeartbeats 1000000 in
/-- **The full trace of `createHeader`'s third loop**: not just the per-iteration size growth but
the actual sequence of `(routingInfo, macBytes)` pairs, one per hop — the content-level fact
`unwrapNIKE`'s peeling side needs, mirroring `createKEMHeader_loop3_trace`. -/
private theorem createHeader_loop3_trace (_nike : NIKE) (macS : MAC) (geom : Geometry)
    (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (nrHops : Nat) (init final : ByteArray × ByteArray)
    (hfinal :
      forIn (List.range' 0 nrHops) init
        (fun iRev (st : ByteArray × ByteArray) =>
          ((fun riFragment0 => ForInStep.yield
              (if !((nrHops - 1 - iRev) == nrHops - 1) then
                (xorBytes (zeroPadTo geom.perHopRoutingInfoLength
                    (riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - iRev + 1]!).id
                      (toVec32 st.2)).toBytes) ++ st.1) (riKeyStream[nrHops - 1 - iRev]!),
                 ofVector (macS.mac (ofVector (keys[nrHops - 1 - iRev]!).headerMAC)
                   (v0AD ++ groupElements[nrHops - 1 - iRev]! ++
                     xorBytes (zeroPadTo geom.perHopRoutingInfoLength
                       (riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - iRev + 1]!).id
                         (toVec32 st.2)).toBytes) ++ st.1) (riKeyStream[nrHops - 1 - iRev]!)
                     ++ (if nrHops - 1 - iRev > 0 then riPadding[nrHops - 1 - iRev - 1]!
                         else ByteArray.empty))))
              else
                (xorBytes (zeroPadTo geom.perHopRoutingInfoLength riFragment0 ++ st.1)
                    (riKeyStream[nrHops - 1 - iRev]!),
                 ofVector (macS.mac (ofVector (keys[nrHops - 1 - iRev]!).headerMAC)
                   (v0AD ++ groupElements[nrHops - 1 - iRev]! ++
                     xorBytes (zeroPadTo geom.perHopRoutingInfoLength riFragment0 ++ st.1)
                       (riKeyStream[nrHops - 1 - iRev]!)
                     ++ (if nrHops - 1 - iRev > 0 then riPadding[nrHops - 1 - iRev - 1]!
                         else ByteArray.empty))))) : ByteArray → ForInStep (ByteArray × ByteArray))
            <$> (commandsToBytes
              (if (nrHops - 1 - iRev) == nrHops - 1 then geom.perHopRoutingInfoLength
               else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
              (path[nrHops - 1 - iRev]!).commands) :
            Except String (ForInStep (ByteArray × ByteArray)))) = Except.ok final) :
    ∃ s : Nat → ByteArray × ByteArray, s 0 = init ∧ s nrHops = final ∧
      ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))) := by
  have hnd : ∀ (b : Nat) (a a' : ByteArray × ByteArray), b ∈ List.range' 0 nrHops →
      (fun iRev (st : ByteArray × ByteArray) =>
        ((fun riFragment0 => ForInStep.yield
            (if !((nrHops - 1 - iRev) == nrHops - 1) then
              (xorBytes (zeroPadTo geom.perHopRoutingInfoLength
                  (riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - iRev + 1]!).id
                    (toVec32 st.2)).toBytes) ++ st.1) (riKeyStream[nrHops - 1 - iRev]!),
               ofVector (macS.mac (ofVector (keys[nrHops - 1 - iRev]!).headerMAC)
                 (v0AD ++ groupElements[nrHops - 1 - iRev]! ++
                   xorBytes (zeroPadTo geom.perHopRoutingInfoLength
                     (riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - iRev + 1]!).id
                       (toVec32 st.2)).toBytes) ++ st.1) (riKeyStream[nrHops - 1 - iRev]!)
                   ++ (if nrHops - 1 - iRev > 0 then riPadding[nrHops - 1 - iRev - 1]!
                       else ByteArray.empty))))
            else
              (xorBytes (zeroPadTo geom.perHopRoutingInfoLength riFragment0 ++ st.1)
                  (riKeyStream[nrHops - 1 - iRev]!),
               ofVector (macS.mac (ofVector (keys[nrHops - 1 - iRev]!).headerMAC)
                 (v0AD ++ groupElements[nrHops - 1 - iRev]! ++
                   xorBytes (zeroPadTo geom.perHopRoutingInfoLength riFragment0 ++ st.1)
                     (riKeyStream[nrHops - 1 - iRev]!)
                   ++ (if nrHops - 1 - iRev > 0 then riPadding[nrHops - 1 - iRev - 1]!
                       else ByteArray.empty))))) : ByteArray → ForInStep (ByteArray × ByteArray))
          <$> (commandsToBytes
            (if (nrHops - 1 - iRev) == nrHops - 1 then geom.perHopRoutingInfoLength
             else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
            (path[nrHops - 1 - iRev]!).commands) :
          Except String (ForInStep (ByteArray × ByteArray)))) b a
        ≠ Except.ok (ForInStep.done a') := by
    intro b a a' _hb hcontra
    simp only [Functor.map, Except.map] at hcontra
    split at hcontra <;> simp_all
  obtain ⟨s, hs0, hsl, hstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
    (List.range' 0 nrHops) _ hnd init final hfinal
  refine ⟨s, hs0, by simpa using hsl, ?_⟩
  intro j hj
  have hj' : j < (List.range' 0 nrHops).length := by simpa using hj
  have hstepj := hstep j hj'
  simp only [List.getElem_range', Nat.one_mul, Nat.zero_add] at hstepj
  obtain ⟨riFragment0, hriFragment0, hstepj⟩ := Except.eq_ok_of_map_eq_ok hstepj
  by_cases hterm : nrHops - 1 - j = nrHops - 1
  · have hcond : (nrHops - 1 - j == nrHops - 1) = true := by simp [hterm]
    have hcond' : (!(nrHops - 1 - j == nrHops - 1)) = false := by simp [hterm]
    simp only [hcond', if_false, Bool.false_eq_true] at hstepj
    simp only [ForInStep.yield.injEq] at hstepj
    have h1 : (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength riFragment0
        ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) := (congrArg Prod.fst hstepj).symm
    have h2 : (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
        (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
          ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))) := by
      rw [h1]; exact (congrArg Prod.snd hstepj).symm
    refine ⟨riFragment0, hriFragment0, ?_, h2⟩
    simpa only [hcond, decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
      Bool.false_eq_true, reduceIte] using h1
  · have hcond : (nrHops - 1 - j == nrHops - 1) = false := by simp [hterm]
    have hcond' : (!(nrHops - 1 - j == nrHops - 1)) = true := by simp [hterm]
    simp only [hcond', if_true] at hstepj
    simp only [ForInStep.yield.injEq] at hstepj
    have h1 : (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
        (riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
          (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) :=
      (congrArg Prod.fst hstepj).symm
    have h2 : (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
        (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
          ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))) := by
      rw [h1]; exact (congrArg Prod.snd hstepj).symm
    refine ⟨riFragment0, hriFragment0, ?_, h2⟩
    simpa only [hcond, decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
      Bool.false_eq_true, reduceIte] using h1


/-- **Sizes along the `createHeader_loop3_trace` trace**: `(s j).1` grows by exactly one
`perHopRoutingInfoLength` per step (`zeroPadTo`'s output width, by `commandsToBytes_size_le` +
`zeroPadTo_size`), and `(s j).2` — once at least one step has run — is always exactly
`macS.tagSize` wide, by the type of `macS.mac` alone. Mirrors `KEMSphinx.createKEMHeader_s_size`. -/
private theorem createHeader_s_size (_nike : NIKE) (macS : MAC) (geom : Geometry)
    (path : Array PathHop) (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength)
    (hnnh : geom.nextNodeHopLength = nextNodeHopLength)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty)))) :
    ∀ j (_hj : j ≤ nrHops), (s j).1.size = (s 0).1.size + j * geom.perHopRoutingInfoLength ∧
      (0 < j → (s j).2.size = macS.tagSize) := by
  intro j hj
  induction j with
  | zero => simp
  | succ j ih =>
    obtain ⟨ih1, -⟩ := ih (by omega)
    obtain ⟨riFragment0, hriFragment0, h1, h2⟩ := hstep j (by omega)
    have hfullsize : (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
        else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
          (toVec32 (s j).2)).toBytes).size ≤ geom.perHopRoutingInfoLength := by
      by_cases hterm : nrHops - 1 - j = nrHops - 1
      · have hcond : ((nrHops - 1 - j) == nrHops - 1) = true := by simp [hterm]
        rw [hcond] at hriFragment0 ⊢
        simp only [if_true]
        exact commandsToBytes_size_le hriFragment0
      · have hcond : ((nrHops - 1 - j) == nrHops - 1) = false := by simp [hterm]
        rw [hcond] at hriFragment0 ⊢
        simp only [Bool.false_eq_true, if_false]
        have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - geom.nextNodeHopLength :=
          commandsToBytes_size_le hriFragment0
        simp only [ByteArray.size_append, RoutingCommand.nextNodeHop_toBytes_size]
        rw [hnnh] at hle0 hperhop
        omega
    refine ⟨?_, fun _ => ?_⟩
    · rw [h1, size_xorBytes, ByteArray.size_append, zeroPadTo_size hfullsize, ih1]; ring
    · rw [h2]; exact Util.Bytes.size_ofVector _

set_option maxHeartbeats 1000000 in
/-- **`createHeader`**'s `hdr.size`: `2 + nike.publicKeySize + geom.routingInfoLength +
macLength`, matching `geom.headerLength` whenever `geom` was actually built for `nike`
(`hvalid`, satisfied by construction for any `Geometry.ofNIKE nike.hpqcName ...`). -/
theorem createHeader_hdr_size (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry) (clientPrivateKey filler : ByteArray)
    (path : Array PathHop) (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (h : createHeader nike macS kdfS streamS geom clientPrivateKey filler path = .ok (hdr, sprpKeys)) :
    hdr.size = geom.headerLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, -, -⟩ := hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  unfold createHeader at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error "sphinx: invalid path" : Except String (ByteArray × Array SPRPKey)) =
        Except.ok (hdr, sprpKeys) := h
    injection h'
  case isFalse =>
    split at h
    case isTrue =>
      have h' : (Except.error "sphinx: invalid filler length" :
          Except String (ByteArray × Array SPRPKey)) = Except.ok (hdr, sprpKeys) := h
      injection h'
    case isFalse =>
      rename_i h1 h2
      simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
        Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl,
        ite_pure_yield, pure_bind] at h
      obtain ⟨clientSk, hSk, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨hop0, hHop0, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨loop1Final, hLoop1, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      obtain ⟨loop3Final, hLoop3, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      have hpos : 0 < path.size := by
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        omega
      have hgen : path.size ≤ geom.nrHops := by
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        omega
      injection h with h
      have hhdr := congrArg Prod.fst h
      simp only at hhdr
      -- `groupElements[0]!`, untouched by loop1 — same argument as `createHeader_hdr_bytesPub`.
      have hidx0 : loop1Final.1[0]! =
          (Array.replicate path.size (ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)))
            : Array ByteArray)[0]! :=
        CryptWalker.Sphinx.Common.List.forIn_congr_of_forall_mem _ _
          (fun (st : Array ByteArray × Array HopKeys × ByteArray) => st.1[0]!)
          (by
            intro a a' i hi hgb
            obtain ⟨ss, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
            injection hgb with hgb
            rw [← hgb]
            exact Array.getElem!_set!_ne a.1 i 0 _ (by obtain ⟨j, -, rfl⟩ := List.mem_range'.mp hi; omega))
          (by
            intro a a' i hi hgb
            obtain ⟨ss, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
            exact absurd hgb (by simp))
          _ _ hLoop1
      have hpub : (ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk))).size
          = nike.publicKeySize := Util.Bytes.size_ofVector _
      have hge0size : loop1Final.1[0]!.size = nike.publicKeySize := by
        rw [hidx0, getElem!_pos _ _ (by simpa using hpos), Array.getElem_replicate, hpub]
      -- `loop3Final.1`'s size, by pushing the per-iteration size growth through the loop.
      have hinit_size :
          (if geom.nrHops > path.size then filler else (ByteArray.empty : ByteArray)).size
            = (geom.nrHops - path.size) * geom.perHopRoutingInfoLength := by
        split
        · next hgt =>
            simp only [Bool.and_eq_true, decide_eq_true_eq, not_and, not_not] at h2
            exact h2 hgt
        · next hle =>
            have : geom.nrHops - path.size = 0 := by omega
            simp only [byteArray_empty_size, this, Nat.zero_mul]
      have hloop3size : loop3Final.1.size =
          (if geom.nrHops > path.size then filler else (ByteArray.empty : ByteArray)).size
            + path.size * geom.perHopRoutingInfoLength := by
        have hraw : (if geom.nrHops > path.size then filler else (ByteArray.empty : ByteArray)).size
            + (List.range' 0 path.size).length * geom.perHopRoutingInfoLength = loop3Final.1.size := by
          refine (CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem (List.range' 0 path.size) _
            (fun (a : ByteArray × ByteArray) => a.1.size) geom.perHopRoutingInfoLength ?_ ?_ _ _ hLoop3).symm
          · intro a a' iRev hiRev hgb
            have hiRev' : iRev < path.size := by
              obtain ⟨j, hj, rfl⟩ := List.mem_range'.mp hiRev; omega
            obtain ⟨riFragment0, hriFragment0, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            by_cases hterm : path.size - 1 - iRev = path.size - 1
            · have hcond : (path.size - 1 - iRev == path.size - 1) = true := by simp [hterm]
              have hcond' : (!(path.size - 1 - iRev == path.size - 1)) = false := by simp [hterm]
              simp only [hcond'] at hgb
              simp only [hcond] at hriFragment0
              simp only [if_true, if_false, Bool.false_eq_true] at hgb hriFragment0
              have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength :=
                commandsToBytes_size_le hriFragment0
              simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
              rw [← congrArg Prod.fst hgb, size_xorBytes, ByteArray.size_append,
                zeroPadTo_size hle0]
              show geom.perHopRoutingInfoLength + a.1.size = a.1.size + geom.perHopRoutingInfoLength
              omega
            · have hcond : (path.size - 1 - iRev == path.size - 1) = false := by simp [hterm]
              have hcond' : (!(path.size - 1 - iRev == path.size - 1)) = true := by simp [hterm]
              simp only [hcond'] at hgb
              simp only [hcond] at hriFragment0
              simp only [if_true, if_false, Bool.false_eq_true] at hgb hriFragment0
              have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - geom.nextNodeHopLength :=
                commandsToBytes_size_le hriFragment0
              have hle1 : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[path.size - 1 - iRev + 1]!).id
                  (toVec32 a.2)).toBytes).size ≤ geom.perHopRoutingInfoLength := by
                simp only [ByteArray.size_append, RoutingCommand.nextNodeHop_toBytes_size]
                omega
              simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
              rw [← congrArg Prod.fst hgb, size_xorBytes, ByteArray.size_append,
                zeroPadTo_size hle1]
              show geom.perHopRoutingInfoLength + a.1.size = a.1.size + geom.perHopRoutingInfoLength
              omega
          · intro a a' iRev hiRev hgb
            obtain ⟨riFragment0, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            split at hgb <;> injection hgb with hgb <;> injection hgb
        simpa [List.length_range'] using hraw.symm
      have hlne : List.range' 0 path.size ≠ [] := by
        simp only [ne_eq, List.range'_eq_nil_iff]; omega
      have hmacsize : loop3Final.2.size = macS.tagSize := by
        refine CryptWalker.Sphinx.Common.List.forIn_const_of_forall_mem (List.range' 0 path.size) hlne
          _ (fun (a : ByteArray × ByteArray) => a.2.size) macS.tagSize ?_ ?_ _ _ hLoop3
        · intro a a' iRev hiRev hgb
          obtain ⟨riFragment0, hriFragment0, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
          by_cases hterm : path.size - 1 - iRev = path.size - 1
          · have hcond' : (!(path.size - 1 - iRev == path.size - 1)) = false := by simp [hterm]
            simp only [hcond'] at hgb
            simp only [if_false, Bool.false_eq_true] at hgb
            simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
            rw [← congrArg Prod.snd hgb]
            exact Util.Bytes.size_ofVector _
          · have hcond' : (!(path.size - 1 - iRev == path.size - 1)) = true := by simp [hterm]
            simp only [hcond'] at hgb
            simp only [if_true] at hgb
            simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
            rw [← congrArg Prod.snd hgb]
            exact Util.Bytes.size_ofVector _
        · intro a a' iRev hiRev hgb
          obtain ⟨riFragment0, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
          split at hgb <;> injection hgb with hgb <;> injection hgb
      have hv0 : v0AD.size = 2 := rfl
      have hmulcombine : (geom.nrHops - path.size) * geom.perHopRoutingInfoLength
          + path.size * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
        rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
      rw [← hhdr]
      simp only [ByteArray.size_append, hv0, hge0size, hloop3size, hinit_size, hmacsize, hmactag]
      rw [hheader, hrouting, ← hmulcombine]
      simp only [adLength, macLength]

/-- **`newNIKEPacket`**. Generic in the wide-block cipher/MAC/KDF/stream cipher, matching
`createKEMHeader`/`unwrapKEM` on the KEM side. -/
def newNIKEPacket (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createHeader nike macS kdfS streamS geom clientPrivateKey filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := cipher.encrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

private theorem newNIKEPacket_bytesPub (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (clientPrivateKey : ByteArray) (filler : ByteArray) (path : Array PathHop)
    (payload : ByteArray) (pkt : ByteArray)
    (h : newNIKEPacket nike cipher macS kdfS streamS geom clientPrivateKey filler path payload
      = .ok pkt) :
    pkt.extract 2 (2 + nike.publicKeySize) = nikeSelfPublicKeyBytes nike clientPrivateKey := by
  unfold newNIKEPacket at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error
        s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}" :
        Except String ByteArray) = Except.ok pkt := h
    injection h'
  case isFalse =>
    simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl,
      pure_bind] at h
    obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
    have hpkt : pkt = x.1 ++ (List.range' 0 [:x.2.size].size).foldl
        (fun b a ↦ cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
        ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload) := by
      injection hfx with hfx; exact hfx.symm
    obtain ⟨hhdrPub, hhdrgePub⟩ := createHeader_hdr_bytesPub nike macS kdfS streamS geom
      clientPrivateKey filler path x.1 x.2 hx
    rw [hpkt, CryptWalker.Util.Bytes.extract_append_of_le _ _ (by omega)]
    exact hhdrPub

/-- A successful `newNIKEPacket` on a `geom.forwardPayloadLength`-sized payload produces exactly
`geom.packetLength` bytes: `headerLength` (`createHeader_hdr_size`) plus `payloadTagLength +
payload.size` (`cipher.encrypt_size`'s length preservation). `wrapNIKE` uses it to give
`Sphinx.Interface.wrap` a packet-length-preserving type. -/
theorem newNIKEPacket_size (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (h : newNIKEPacket nike cipher macS kdfS streamS geom clientPrivateKey filler path payload
      = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  unfold newNIKEPacket at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error
        s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}" :
        Except String ByteArray) = Except.ok pkt := h
    injection h'
  case isFalse =>
    simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
      Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind] at h
    obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
    have hpkt : pkt = x.1 ++ (List.range' 0 x.2.size).foldl
        (fun b a ↦ cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
        ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload) := by
      injection hfx with hfx; exact hfx.symm
    have hhdrsize := createHeader_hdr_size nike macS kdfS streamS geom clientPrivateKey filler path
      x.1 x.2 hvalid hmactag hx
    have hfoldsize := CryptWalker.Sphinx.Common.List.foldl_size_preserving (List.range' 0 x.2.size)
      (fun b a ↦ cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
      (fun b a ↦ cipher.encrypt_size _ _ b)
      ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload)
    rw [hpkt, ByteArray.size_append, hhdrsize, hfoldsize, ByteArray.size_append, hpacket]
    simp only [byteArray_mk_size, Array.size_replicate]
    omega

/-- `newNIKEPacket`'s payload loop's one-step accumulator update — never fails, so its `forIn`
collapses to a bare `List.foldl` under `List.forIn_pure_yield_eq_foldl`. Mirrors
`KEMSphinx.payloadEncryptStep` (the payload-encryption loop is byte-identical between the two
schemes: both layer `sprpKeys` back-to-front over the tag-prefixed payload). -/
private def payloadEncryptStep (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (b : ByteArray) (iRev : Nat) : ByteArray :=
  let k := sprpKeys[sprpKeys.size - 1 - iRev]!
  cipher.encrypt k.key.toArray (ofVector k.iv) b

/-- **The full trace of `newNIKEPacket`'s payload-encryption loop.** -/
private theorem newNIKEPacket_payload_trace (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (init : ByteArray) :
    ∃ t : Nat → ByteArray, t 0 = init ∧
      t sprpKeys.size = (List.range' 0 sprpKeys.size).foldl (payloadEncryptStep cipher sprpKeys) init ∧
      ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j := by
  obtain ⟨t, ht0, htl, hstep⟩ := CryptWalker.Sphinx.Common.List.foldl_exists_trace
    (List.range' 0 sprpKeys.size) (payloadEncryptStep cipher sprpKeys) init
  refine ⟨t, ht0, by simpa using htl, ?_⟩
  intro j hj
  have hj' : j < (List.range' 0 sprpKeys.size).length := by simpa using hj
  simpa using hstep j hj'

/-- **The payload-layering invariant, at the content level**: writing `payloadAt k := t
(sprpKeys.size - k)` for the trace above, hop `k` recovers `payloadAt (k+1)` from `payloadAt k`
by decrypting with exactly *its own* `sprpKeys[k]!` — the SPRP-layering fact `unwrapNIKE`'s
payload decryption at each hop needs. -/
private theorem newNIKEPacket_payload_content (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (t : Nat → ByteArray)
    (hstep : ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (k : Nat) (hk : k < sprpKeys.size) :
    t (sprpKeys.size - k) = cipher.encrypt (sprpKeys[k]!).key.toArray (ofVector (sprpKeys[k]!).iv)
      (t (sprpKeys.size - (k + 1))) := by
  have hstepk := hstep (sprpKeys.size - k - 1) (by omega)
  rw [show sprpKeys.size - k - 1 + 1 = sprpKeys.size - k from by omega] at hstepk
  unfold payloadEncryptStep at hstepk
  rw [show sprpKeys.size - 1 - (sprpKeys.size - k - 1) = k from by omega] at hstepk
  rw [hstepk, show sprpKeys.size - (k + 1) = sprpKeys.size - k - 1 from by omega]

/-- The payload trace never changes size — `cipher.encrypt` preserves length at every step. -/
private theorem newNIKEPacket_payload_size_trace (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (t : Nat → ByteArray)
    (hstep : ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j) :
    ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size := by
  intro j hj
  induction j with
  | zero => rfl
  | succ j ih =>
    rw [hstep j (by omega)]
    unfold payloadEncryptStep
    rw [cipher.encrypt_size]
    exact ih (by omega)

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **`createHeader`, fully unfolded to content.** Packages the loop1 blinding-chain content, the
loop2 (`riKeyStream`/`riPadding`) content, and the loop3 trace — plus the `hdr`/`sprpKeys`
assembly itself — behind one hypothesis, in the exact shape a successful `createHeader` call
unfolds to, so `groupElements`/`keys` are shared between the blinding-chain content and loop3's
step formula with no cross-theorem array-equality needed. Mirrors `createKEMHeader_unfold`,
though loop1's induction is inlined here rather than factored out, since NIKE's nested
inner re-blinding loop makes a standalone signature unwieldy. -/
private theorem createHeader_unfold (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry) (clientPrivateKey filler : ByteArray) (path : Array PathHop)
    (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (h : createHeader nike macS kdfS streamS geom clientPrivateKey filler path = .ok (hdr, sprpKeys))
    (targetSk : Nat → nike.PrivateKey)
    (htarget : ∀ i (_hi : i < path.size), (path[i]!).publicKey
      = ofVector (nike.encodePublicKey (nike.derivePublicKey (targetSk i)))) :
    path.size ≠ 0 ∧ path.size ≤ geom.nrHops ∧
    (geom.nrHops > path.size → filler.size = (geom.nrHops - path.size) * geom.perHopRoutingInfoLength) ∧
    ∃ (clientSk : nike.PrivateKey) (f : Nat → nike.PrivateKey)
      (groupElements : Array ByteArray) (keys : Array HopKeys)
      (riKeyStream riPadding : Array ByteArray) (s : Nat → ByteArray × ByteArray),
      groupElements.size = path.size ∧ keys.size = path.size ∧
      riKeyStream.size = path.size ∧ riPadding.size = path.size ∧
      nikeSelfPublicKeyBytes nike clientPrivateKey
        = ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)) ∧
      (∀ i (_hi : i < path.size),
        groupElements[i]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f i).1) ∧
        keys[i]! = deriveHopKeys kdfS
          (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk i) f i).1)) ∧
        nike.decodePrivateKey (toVecN nike.privateKeySize (keys[i]!).blindingFactor) = some (f i)) ∧
      (∀ i (_hi : i < path.size),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength) ∧
        riPadding[i]! =
          (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
           let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
             (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
           let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
           let thisPad0 := ks.extract ksLen totalRiLen
           if i > 0 then
             xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
               ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
           else thisPad0)) ∧
      s 0 = (if geom.nrHops > path.size then filler else ByteArray.empty, ByteArray.empty) ∧
      (∀ j (_hj : j < path.size), ∃ riFragment0,
        commandsToBytes
          (if (path.size - 1 - j) == path.size - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[path.size - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (path.size - 1 - j) == path.size - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[path.size - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[path.size - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[path.size - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[path.size - 1 - j]! ++ (s (j + 1)).1
            ++ (if path.size - 1 - j > 0 then riPadding[path.size - 1 - j - 1]! else ByteArray.empty)))) ∧
      hdr = v0AD ++ groupElements[0]! ++ (s path.size).1 ++ (s path.size).2 ∧
      sprpKeys = Array.ofFn (fun i : Fin path.size =>
        { key := keys[i.val]!.payloadEncryption, iv := keys[i.val]!.headerEncryptionIV }) := by
  unfold createHeader at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error "sphinx: invalid path" : Except String (ByteArray × Array SPRPKey)) =
        Except.ok (hdr, sprpKeys) := h
    injection h'
  case isFalse =>
    split at h
    case isTrue =>
      have h' : (Except.error "sphinx: invalid filler length" : Except String (ByteArray × Array SPRPKey)) =
          Except.ok (hdr, sprpKeys) := h
      injection h'
    case isFalse =>
      rename_i h1 h2
      simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
        Nat.add_sub_cancel, Nat.div_one, ite_pure_yield, bind_pure_comp] at h
      obtain ⟨clientSk, hSk, hA⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
      clear h
      obtain ⟨hop0, hHop0, hB⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hA
      clear hA
      obtain ⟨loop1Final, hLoop1, hC⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hB
      clear hB
      obtain ⟨loop2Final, hLoop2, hC2⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hC
      clear hC
      obtain ⟨loop3Final, hLoop3, hD⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hC2
      clear hC2
      obtain ⟨s1, hs01, hsl1, hstep1⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace _ _
        (by
          intro a a' i hi hgb
          obtain ⟨ss, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
          obtain ⟨y', -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hgb
          exact absurd hgb (by simp))
        _ _ hLoop1
      clear hLoop1
      have hpos : 0 < path.size := by
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        omega
      have hgen : path.size ≤ geom.nrHops := by
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        omega
      have hlen1 : (List.range' 1 (path.size - 1)).length = path.size - 1 := by simp
      have hSk' : nike.decodePrivateKey (toVecN nike.privateKeySize clientPrivateKey) = some clientSk := by
        unfold nikeDecodePrivateKey at hSk
        match hd : nike.decodePrivateKey (toVecN nike.privateKeySize clientPrivateKey), hSk with
        | none, hSk => injection hSk
        | some sk, hSk =>
          simp only [pure, Except.pure, Except.ok.injEq] at hSk
          exact congrArg some hSk
      have hself : nikeSelfPublicKeyBytes nike clientPrivateKey =
          ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk)) := by
        unfold nikeSelfPublicKeyBytes
        rw [hSk']
      obtain ⟨f, hf⟩ :
          ∃ f : Nat → nike.PrivateKey, ∀ j,
            nike.decodePrivateKey (toVecN nike.privateKeySize ((s1 j).2.1[j]!).blindingFactor) = some (f j) :=
        ⟨fun j => (nike.decodePrivateKey_total (toVecN nike.privateKeySize ((s1 j).2.1[j]!).blindingFactor)).choose,
          fun j => (nike.decodePrivateKey_total (toVecN nike.privateKeySize ((s1 j).2.1[j]!).blindingFactor)).choose_spec⟩
      have hsize : ∀ j, j ≤ path.size - 1 → (s1 j).2.1.size = j + 1 := by
        intro j
        induction j with
        | zero =>
          intro _
          rw [hs01]
          rfl
        | succ j ih =>
          intro hj
          have hj' : j < (List.range' 1 (path.size - 1)).length := by rw [hlen1]; omega
          obtain ⟨sharedSecret0, -, hrest⟩ :=
            CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok (hstep1 j hj')
          obtain ⟨finalSS, -, hyieldEq⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hrest
          injection hyieldEq with hyieldEq
          have hkeyseq : (s1 (j+1)).2.1 = (s1 j).2.1.push (deriveHopKeys kdfS finalSS) :=
            (congrArg (fun p => p.2.1) hyieldEq).symm
          rw [hkeyseq, Array.size_push, ih (by omega)]
      have hpush : ∀ j, j < path.size - 1 → ∃ x, (s1 (j+1)).2.1 = (s1 j).2.1.push x := by
        intro j hj
        have hj' : j < (List.range' 1 (path.size - 1)).length := by rw [hlen1]; omega
        obtain ⟨sharedSecret0, -, hrest⟩ :=
          CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok (hstep1 j hj')
        obtain ⟨finalSS, -, hyieldEq⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hrest
        injection hyieldEq with hyieldEq
        exact ⟨deriveHopKeys kdfS finalSS, (congrArg (fun p => p.2.1) hyieldEq).symm⟩
      have hsetG : ∀ j, j < path.size - 1 → ∃ x, (s1 (j+1)).1 = (s1 j).1.set! (j+1) x := by
        intro j hj
        have hj' : j < (List.range' 1 (path.size - 1)).length := by rw [hlen1]; omega
        have hstepj := hstep1 j hj'
        rw [List.getElem_range'_1 j hj', Nat.add_comm] at hstepj
        obtain ⟨sharedSecret0, -, hrest⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hstepj
        obtain ⟨finalSS, -, hyieldEq⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hrest
        injection hyieldEq with hyieldEq
        exact ⟨nikeBlind nike (s1 j).2.2 ((s1 j).2.1.push (deriveHopKeys kdfS finalSS))[j]!.blindingFactor,
          (congrArg (fun p => p.1) hyieldEq).symm⟩
      have hfreezeG : ∀ i m, i ≤ m → m ≤ path.size - 1 → (s1 m).1[i]! = (s1 i).1[i]! := by
        intro i m him hmn
        induction m with
        | zero => have : i = 0 := by omega
                  rw [this]
        | succ m ih =>
          rcases Nat.lt_or_ge i (m + 1) with h | h
          · obtain ⟨x, hx⟩ := hsetG m (by omega)
            rw [hx, Array.getElem!_set!_ne _ _ _ _ (by omega)]
            exact ih (by omega) (by omega)
          · have : i = m + 1 := by omega
            rw [this]
      have hsizeG : ∀ j, j ≤ path.size - 1 → (s1 j).1.size = path.size := by
        intro j
        induction j with
        | zero => intro _; rw [hs01]; exact Array.size_replicate
        | succ j ih =>
          intro hj
          have hj' : j < (List.range' 1 (path.size - 1)).length := by rw [hlen1]; omega
          have hstepj := hstep1 j hj'
          rw [List.getElem_range'_1 j hj', Nat.add_comm] at hstepj
          obtain ⟨sharedSecret0, -, hrest⟩ :=
            CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hstepj
          obtain ⟨finalSS, -, hyieldEq⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hrest
          injection hyieldEq with hyieldEq
          have hEeq0 : (s1 (j+1)).1 = (s1 j).1.set! (j+1)
              (nikeBlind nike (s1 j).2.2 ((s1 j).2.1.push (deriveHopKeys kdfS finalSS))[j]!.blindingFactor) :=
            (congrArg (fun p => p.1) hyieldEq).symm
          rw [hEeq0, Array.size_set!, ih (by omega)]
      have main0 : (s1 0).1[0]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f 0).1) ∧
          (s1 0).2.1[0]! = deriveHopKeys kdfS
            (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk 0) f 0).1)) ∧
          (s1 0).2.2 = (s1 0).1[0]! := by
        rw [hs01]
        dsimp only
        refine ⟨?_, ?_, ?_⟩
        · rw [getElem!_pos _ 0 (by simpa using hpos), Array.getElem_replicate]
          rfl
        · have heq : hop0 = ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk 0) f 0).1) := by
            rw [htarget 0 hpos] at hHop0
            rw [nikeDH_bridge nike clientSk (nike.derivePublicKey (targetSk 0)) (nike.derive_safe (targetSk 0))]
              at hHop0
            injection hHop0 with hHop0
            exact hHop0.symm
          rw [getElem!_pos _ 0 (by simp)]
          exact congrArg (deriveHopKeys kdfS) heq
        · rw [getElem!_pos _ 0 (by simpa using hpos), Array.getElem_replicate]
      have main : ∀ m, m < path.size →
          (s1 m).1[m]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f m).1) ∧
          (s1 m).2.1[m]! = deriveHopKeys kdfS
            (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk m) f m).1)) ∧
          (s1 m).2.2 = (s1 m).1[m]! := by
        intro m
        induction m with
        | zero => intro _; exact main0
        | succ m ih =>
          intro hm
          have hm' : m < path.size := by omega
          obtain ⟨ihE, ihS, ihP⟩ := ih hm'
          have hj' : m < (List.range' 1 (path.size - 1)).length := by rw [hlen1]; omega
          have hstepm := hstep1 m hj'
          rw [List.getElem_range'_1 m hj', Nat.add_comm] at hstepm
          obtain ⟨sharedSecret0, hss0, hrest⟩ :=
            CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hstepm
          obtain ⟨finalSS, hfinalSS, hyieldEq⟩ :=
            CryptWalker.Sphinx.Common.Except.eq_ok_of_map_eq_ok hrest
          injection hyieldEq with hyieldEq
          have hEeq : (s1 (m + 1)).1 = (s1 m).1.set! (m + 1)
              (nikeBlind nike (s1 m).2.2 ((s1 m).2.1.push (deriveHopKeys kdfS finalSS))[m]!.blindingFactor) :=
            (congrArg (fun p => p.1) hyieldEq).symm
          have hSeq : (s1 (m + 1)).2.1 = (s1 m).2.1.push (deriveHopKeys kdfS finalSS) :=
            (congrArg (fun p => p.2.1) hyieldEq).symm
          have hPeq : (s1 (m + 1)).2.2 = nikeBlind nike (s1 m).2.2
              ((s1 m).2.1.push (deriveHopKeys kdfS finalSS))[m]!.blindingFactor :=
            (congrArg (fun p => p.2.2) hyieldEq).symm
          have hfactor_eq : ∀ k (hk : k < m + 1),
              nike.decodePrivateKey (toVecN nike.privateKeySize ((s1 m).2.1[k]!).blindingFactor)
                = some (f k) := by
            intro k hk
            rw [Array.getElem!_stable_from_pushes (fun j => (s1 j).2.1) (path.size - 1) hpush hsize k m
              (by omega) (by omega)]
            exact hf k
          have htarget' : path[m + 1]!.publicKey
              = ofVector (nike.encodePublicKey (nike.derivePublicKey (targetSk (m + 1)))) :=
            htarget (m + 1) (by omega)
          have hfinalSS_eq := nikeDH_innerLoop_bridge nike clientSk (targetSk (m + 1)) path[m + 1]!.publicKey
            htarget' (fun k => ((s1 m).2.1[k]!).blindingFactor) f (m + 1) hfactor_eq sharedSecret0 finalSS
            hss0 hfinalSS
          have hstableKeyEq : ((s1 m).2.1.push (deriveHopKeys kdfS finalSS))[m]! = (s1 m).2.1[m]! :=
            CryptWalker.Sphinx.Common.Array.getElem!_push_stable _ _ _ (by rw [hsize m (by omega)]; omega)
          have hX : nikeBlind nike (s1 m).2.2 ((s1 m).2.1.push (deriveHopKeys kdfS finalSS))[m]!.blindingFactor
              = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f (m + 1)).1) := by
            rw [hstableKeyEq, ihP, ihE]
            exact nikeBlind_bridge nike (telescopeElem nike clientSk f m).1 (f m)
              (telescopeElem nike clientSk f m).2 _ (hf m)
          have hpushedEq : ((s1 m).2.1.push (deriveHopKeys kdfS finalSS))[m + 1]! = deriveHopKeys kdfS finalSS := by
            have hsz : (s1 m).2.1.size = m + 1 := hsize m (by omega)
            rw [← hsz, getElem!_pos _ _ (by rw [Array.size_push]; omega), Array.getElem_push_eq]
          refine ⟨?_, ?_, ?_⟩
          · rw [hEeq, Array.getElem!_set!_self _ _ _ (by rw [hsizeG m (by omega)]; omega), hX]
          · rw [hSeq, hpushedEq, ← hfinalSS_eq]
          · rw [hPeq, hX, hEeq, Array.getElem!_set!_self _ _ _ (by rw [hsizeG m (by omega)]; omega), hX]
      have hsl1' : s1 (path.size - 1) = loop1Final := by rw [hlen1] at hsl1; exact hsl1
      -- Loop1's content, in terms of `loop1Final` directly.
      have hgsize : loop1Final.1.size = path.size := by rw [← hsl1']; exact hsizeG (path.size - 1) (le_refl _)
      have hksize0 : loop1Final.2.1.size = path.size := by
        rw [← hsl1']; rw [hsize (path.size - 1) (le_refl _)]; omega
      have hgcontent : ∀ i (hi : i < path.size),
          loop1Final.1[i]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f i).1) ∧
          loop1Final.2.1[i]! = deriveHopKeys kdfS
            (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk i) f i).1)) ∧
          nike.decodePrivateKey (toVecN nike.privateKeySize (loop1Final.2.1[i]!).blindingFactor) = some (f i) := by
        intro i hi
        obtain ⟨mE, mS, -⟩ := main i hi
        have hE : loop1Final.1[i]! = (s1 i).1[i]! := by
          rw [← hsl1']; exact hfreezeG i (path.size - 1) (by omega) (le_refl _)
        have hS : loop1Final.2.1[i]! = (s1 i).2.1[i]! := by
          rw [← hsl1']
          exact Array.getElem!_stable_from_pushes (fun j => (s1 j).2.1)
            (path.size - 1) hpush hsize i (path.size - 1) (by omega) (le_refl _)
        refine ⟨?_, ?_, ?_⟩
        · rw [hE]; exact mE
        · rw [hS]; exact mS
        · rw [hS]; exact hf i
      -- Loop2, using its own raw `forIn` directly (no `List.forIn_pure_yield_eq_foldl`
      -- collapsing, since the elaborated term shape doesn't match what that collapse produces).
      have hloop2content : ∀ i (hi : i < path.size),
          loop2Final.1[i]! = (streamS.keystream (ofVector (loop1Final.2.1[i]!).headerEncryption)
              (ofVector (loop1Final.2.1[i]!).headerEncryptionIV)
              (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
            ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
              - (i + 1) * geom.perHopRoutingInfoLength) ∧
          loop2Final.2[i]! =
            (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
             let ks := streamS.keystream (ofVector (loop1Final.2.1[i]!).headerEncryption)
               (ofVector (loop1Final.2.1[i]!).headerEncryptionIV) totalRiLen
             let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
             let thisPad0 := ks.extract ksLen totalRiLen
             if i > 0 then
               xorBytes (thisPad0.extract 0 loop2Final.2[i - 1]!.size) loop2Final.2[i - 1]!
                 ++ thisPad0.extract loop2Final.2[i - 1]!.size thisPad0.size
             else thisPad0) :=
        fun i hi => createHeader_loop2_content_native streamS geom loop1Final.2.1 path.size loop2Final hLoop2 i hi
      have hriKSsize : loop2Final.1.size = path.size := by
        obtain ⟨s2, hs02, hsl2, hstep2⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
          (List.range' 0 path.size) _
          (by
            intro a a' i hi hgb
            simp only [pure, Except.pure, Except.ok.injEq] at hgb
            split at hgb <;> injection hgb)
          _ _ hLoop2
        have hlen2 : (List.range' 0 path.size).length = path.size := by simp
        have hsl2' : s2 path.size = loop2Final := by rw [← hlen2]; exact hsl2
        have hsize2 : ∀ j (hj : j ≤ path.size), (s2 j).1.size = j := by
          intro j hj
          induction j with
          | zero => simp [hs02]
          | succ j ih =>
            have hj' : j < (List.range' 0 path.size).length := by rw [hlen2]; omega
            have hstepj := hstep2 j hj'
            simp only [List.getElem_range', Nat.zero_add] at hstepj
            split at hstepj <;>
              · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
                rw [← congrArg Prod.fst hstepj]; simp [ih (by omega)]
        rw [← hsl2']; exact hsize2 path.size (le_refl _)
      have hriPadsize : loop2Final.2.size = path.size := by
        obtain ⟨s2, hs02, hsl2, hstep2⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
          (List.range' 0 path.size) _
          (by
            intro a a' i hi hgb
            simp only [pure, Except.pure, Except.ok.injEq] at hgb
            split at hgb <;> injection hgb)
          _ _ hLoop2
        have hlen2 : (List.range' 0 path.size).length = path.size := by simp
        have hsl2' : s2 path.size = loop2Final := by rw [← hlen2]; exact hsl2
        have hsize2 : ∀ j (hj : j ≤ path.size), (s2 j).2.size = j := by
          intro j hj
          induction j with
          | zero => simp [hs02]
          | succ j ih =>
            have hj' : j < (List.range' 0 path.size).length := by rw [hlen2]; omega
            have hstepj := hstep2 j hj'
            simp only [List.getElem_range', Nat.zero_add] at hstepj
            split at hstepj <;>
              · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
                rw [← congrArg Prod.snd hstepj]; simp [ih (by omega)]
        rw [← hsl2']; exact hsize2 path.size (le_refl _)
      -- Loop3, using the SAME `loop1Final`/`loop2Final` this whole proof has been built on.
      obtain ⟨s3, hs03, hsl3, hstep3⟩ := createHeader_loop3_trace nike macS geom path loop1Final.2.1
        loop1Final.1 loop2Final.1 loop2Final.2 path.size
        (if geom.nrHops > path.size then filler else ByteArray.empty, ByteArray.empty) loop3Final hLoop3
      injection hD with hD
      have hhdreq : hdr = v0AD ++ loop1Final.1[0]! ++ loop3Final.1 ++ loop3Final.2 :=
        (congrArg Prod.fst hD).symm
      have hsprpeq : sprpKeys = Array.ofFn (fun i : Fin path.size =>
          { key := loop1Final.2.1[i.val]!.payloadEncryption, iv := loop1Final.2.1[i.val]!.headerEncryptionIV }) :=
        (congrArg Prod.snd hD).symm
      refine ⟨hpos.ne', hgen, ?_, clientSk, f, loop1Final.1, loop1Final.2.1, loop2Final.1, loop2Final.2,
        s3, hgsize, hksize0, hriKSsize, hriPadsize, hself, hgcontent, hloop2content, hs03, hstep3, ?_, hsprpeq⟩
      · intro hgt
        simp only [Bool.and_eq_true, decide_eq_true_eq, not_and, not_not] at h2
        exact h2 hgt
      · rw [hhdreq, ← hsl3]

/-- **`newNIKEPacket`, fully unfolded to content.** As `createHeader_hdr_size`'s own opening moves:
packages `createHeader`'s own success and the payload-encryption trace
(`newNIKEPacket_payload_trace`) behind one hypothesis, in the shape a successful `newNIKEPacket`
call actually unfolds to. Mirrors `KEMSphinx.newKEMPacket_unfold`. -/
private theorem newNIKEPacket_unfold (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newNIKEPacket nike cipher macS kdfS streamS geom clientPrivateKey filler path payload
      = Except.ok pkt) :
    payload.size = geom.forwardPayloadLength ∧
    ∃ (hdr : ByteArray) (sprpKeys : Array SPRPKey) (t : Nat → ByteArray),
      createHeader nike macS kdfS streamS geom clientPrivateKey filler path = Except.ok (hdr, sprpKeys) ∧
      t 0 = (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload ∧
      (∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j) ∧
      pkt = hdr ++ t sprpKeys.size := by
  unfold newNIKEPacket at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error
        s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}" :
        Except String ByteArray) = Except.ok pkt := h
    injection h'
  case isFalse =>
    rename_i hpay
    simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
      Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind] at h
    obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
    obtain ⟨t, ht0, htl, hstep⟩ := newNIKEPacket_payload_trace cipher x.2
      ((⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload)
    refine ⟨by omega, x.1, x.2, t, hx, ht0, hstep, ?_⟩
    injection hfx with hfx
    have hfeq : (fun b a => cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray
        (ofVector x.2[x.2.size - 1 - a]!.iv) b) = payloadEncryptStep cipher x.2 := rfl
    rw [hfeq] at hfx
    rw [← hfx, htl]

/-- **The packet arriving at hop `k`** (`0 ≤ k < nrHops`), assembled from `createHeader`'s
`groupElements`/`riPadding`/loop3 trace `s` and `newNIKEPacket`'s payload trace `t`. Mirrors
`KEMSphinx.hopPacket`, with `groupElements[k]!` (this hop's re-blinded group element, width
`nike.publicKeySize`) in place of `kemElements[k]!` (an independent per-hop ciphertext, width
`kem.ciphertextSize`) — the one structural difference between the two schemes' wire formats. -/
private def hopPacket (groupElements riPadding : Array ByteArray) (s : Nat → ByteArray × ByteArray)
    (t : Nat → ByteArray) (nrHops k : Nat) : ByteArray :=
  v0AD ++ groupElements[k]! ++ ((s (nrHops - k)).1 ++ (if k > 0 then riPadding[k - 1]! else ByteArray.empty))
    ++ (s (nrHops - k)).2 ++ t (nrHops - k)

/-- **`hopPacket`'s size**: exactly `geom.packetLength`, for every `k < nrHops` — the routing-info
slot (`R(k) ++ P(k-1)`) is always exactly `geom.routingInfoLength` bytes regardless of `k`, matching
the classical Sphinx invariant that the wire format never changes size as a packet is forwarded.
Mirrors `KEMSphinx.hopPacket_size`. -/
private theorem hopPacket_size (nike : NIKE) (macS : MAC) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hgnsize : groupElements.size = nrHops)
    (hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize)
    (hpadsize : ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (htsize : ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops) (k : Nat) (hk : k < nrHops) :
    (hopPacket groupElements riPadding s t nrHops k).size = geom.packetLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  have hssize := createHeader_s_size nike macS geom path keys groupElements riKeyStream riPadding
    hperhop hnnh nrHops s hstep
  have hR : (s (nrHops - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength + (nrHops - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - k) (by omega)).1
  have hM : (s (nrHops - k)).2.size = macS.tagSize := (hssize (nrHops - k) (by omega)).2 (by omega)
  have hcts : groupElements[k]!.size = nike.publicKeySize := by
    rw [getElem!_pos groupElements k (by omega)]; exact hgesize k (by omega)
  have hv0 : v0AD.size = 2 := rfl
  have hcombine : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + nrHops * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
  have hnrHmul : (nrHops - k) * geom.perHopRoutingInfoLength + k * geom.perHopRoutingInfoLength
      = nrHops * geom.perHopRoutingInfoLength := by
    rw [← Nat.add_mul]; congr 1; omega
  have hadL : adLength = 2 := rfl
  have hmacL : macLength = 32 := rfl
  unfold hopPacket
  simp only [ByteArray.size_append]
  rw [hcts, hM, hmactag, htsize (nrHops - k) (by omega), ht0size, hv0, hR]
  simp only [hheader, hpacket, hrouting, hadL, hmacL] at *
  split
  · next hk0 =>
    rw [hpadsize (k - 1) (by omega)]
    have : (k - 1 + 1) = k := by omega
    rw [this]
    omega
  · next hk0 =>
    simp only [byteArray_empty_size]
    have hkeq0 : k = 0 := by omega
    rw [hkeq0] at hnrHmul ⊢
    simp only [Nat.sub_zero, Nat.zero_mul, Nat.add_zero] at hnrHmul ⊢
    omega

/-- **`hopPacket`'s five wire-format slices**, spelled out at the exact byte offsets `unwrapNIKE`
reads them at (`geOff = 2`, `riOff = geOff + nike.publicKeySize`, `macOff = riOff +
routingInfoLength`, `payloadOff = macOff + macLength`) — the fact `unwrapNIKE`'s own extracts need
to match against a packet built by `hopPacket`, one slice at a time. Shares `hopPacket_size`'s
hypotheses and its proof's opening moves. Mirrors `KEMSphinx.hopPacket_slices`. -/
private theorem hopPacket_slices (nike : NIKE) (macS : MAC) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hgnsize : groupElements.size = nrHops)
    (hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize)
    (hpadsize : ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (_htsize : ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (_ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops) (k : Nat) (hk : k < nrHops) :
    (hopPacket groupElements riPadding s t nrHops k).extract 0 2 = v0AD ∧
    (hopPacket groupElements riPadding s t nrHops k).extract 2 (2 + nike.publicKeySize)
      = groupElements[k]! ∧
    (hopPacket groupElements riPadding s t nrHops k).extract (2 + nike.publicKeySize)
        (2 + nike.publicKeySize + geom.routingInfoLength)
      = (s (nrHops - k)).1 ++ (if k > 0 then riPadding[k - 1]! else ByteArray.empty) ∧
    (hopPacket groupElements riPadding s t nrHops k).extract
        (2 + nike.publicKeySize + geom.routingInfoLength)
        (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
      = (s (nrHops - k)).2 ∧
    (hopPacket groupElements riPadding s t nrHops k).extract
        (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
        (hopPacket groupElements riPadding s t nrHops k).size
      = t (nrHops - k) := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  have hssize := createHeader_s_size nike macS geom path keys groupElements riKeyStream riPadding
    hperhop hnnh nrHops s hstep
  have hR : (s (nrHops - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength + (nrHops - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - k) (by omega)).1
  have hM : (s (nrHops - k)).2.size = macS.tagSize := (hssize (nrHops - k) (by omega)).2 (by omega)
  have hcts : groupElements[k]!.size = nike.publicKeySize := by
    rw [getElem!_pos groupElements k (by omega)]; exact hgesize k (by omega)
  have hv0 : v0AD.size = 2 := rfl
  have hcombine : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + nrHops * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
  have hnrHmul : (nrHops - k) * geom.perHopRoutingInfoLength + k * geom.perHopRoutingInfoLength
      = nrHops * geom.perHopRoutingInfoLength := by
    rw [← Nat.add_mul]; congr 1; omega
  -- The routing-info slot's total width is always exactly `geom.routingInfoLength`, regardless
  -- of `k` — the same arithmetic `hopPacket_size` needs, extracted here as its own fact.
  have hRPsize : (s (nrHops - k)).1.size
      + (if k > 0 then riPadding[k - 1]! else ByteArray.empty).size = geom.routingInfoLength := by
    rw [hrouting, hR]
    split
    · next hk0 =>
      rw [hpadsize (k - 1) (by omega), show (k - 1 + 1) = k from by omega]
      omega
    · next hk0 =>
      simp only [byteArray_empty_size]
      have hkeq0 : k = 0 := by omega
      rw [hkeq0] at hnrHmul ⊢
      simp only [Nat.sub_zero, Nat.zero_mul, Nat.add_zero] at hnrHmul ⊢
      omega
  unfold hopPacket
  generalize hRPeq : (s (nrHops - k)).1 ++ (if k > 0 then riPadding[k - 1]! else ByteArray.empty) = RP
  have hRPsize' : RP.size = geom.routingInfoLength := by
    rw [← hRPeq, ByteArray.size_append]; exact hRPsize
  generalize hCTeq : groupElements[k]! = CT at hcts ⊢
  generalize hM2eq : (s (nrHops - k)).2 = M2 at hM ⊢
  generalize hT2eq : t (nrHops - k) = T2
  have hABsize : (v0AD ++ CT).size = 2 + nike.publicKeySize := by
    simp only [ByteArray.size_append]; rw [hv0, hcts]
  have hABCsize : (v0AD ++ CT ++ RP).size = 2 + nike.publicKeySize + geom.routingInfoLength := by
    simp only [ByteArray.size_append]; rw [hv0, hcts, hRPsize']
  have hABCDsize : (v0AD ++ CT ++ RP ++ M2).size
      = 2 + nike.publicKeySize + geom.routingInfoLength + macLength := by
    simp only [ByteArray.size_append]; rw [hv0, hcts, hRPsize', hM, hmactag]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rw [extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT).size),
      extract_append_of_le _ _ (by rw [hv0] : (2 : Nat) ≤ v0AD.size)]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize ≤ (v0AD ++ CT).size),
      extract_append_of_ge _ _ (by rw [hv0] : v0AD.size ≤ 2),
      show (2 : Nat) - v0AD.size = 0 from by rw [hv0],
      show 2 + nike.publicKeySize - v0AD.size = nike.publicKeySize from by rw [hv0]; omega]
    rw [← hcts]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize + geom.routingInfoLength
        ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize + geom.routingInfoLength
        ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_ge _ _ (by omega : (v0AD ++ CT).size ≤ 2 + nike.publicKeySize),
      show 2 + nike.publicKeySize - (v0AD ++ CT).size = 0 from by omega,
      show 2 + nike.publicKeySize + geom.routingInfoLength - (v0AD ++ CT).size
        = RP.size from by omega]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + nike.publicKeySize + geom.routingInfoLength + macLength
        ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_ge _ _ (by omega : (v0AD ++ CT ++ RP).size
        ≤ 2 + nike.publicKeySize + geom.routingInfoLength),
      show 2 + nike.publicKeySize + geom.routingInfoLength - (v0AD ++ CT ++ RP).size = 0
        from by omega,
      show 2 + nike.publicKeySize + geom.routingInfoLength + macLength - (v0AD ++ CT ++ RP).size
        = M2.size from by omega]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_ge _ _ (by omega :
        (v0AD ++ CT ++ RP ++ M2).size ≤ 2 + nike.publicKeySize + geom.routingInfoLength + macLength),
      show 2 + nike.publicKeySize + geom.routingInfoLength + macLength - (v0AD ++ CT ++ RP ++ M2).size
        = 0 from by omega,
      show (v0AD ++ CT ++ RP ++ M2 ++ T2).size - (v0AD ++ CT ++ RP ++ M2).size = T2.size
        from by simp only [ByteArray.size_append]; omega]
    exact ByteArray.extract_zero_size

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapNIKE`**: `Sphinx.Interface.wrap` for `NIKESphinxScheme` — `newNIKEPacket`, drawing the
client's ephemeral private key from the seed stream instead of taking it as a bare argument. -/
def wrapNIKE (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seed ← nextSeed
  match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector seed) filler path.toArray
      (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    if hsize : pkt.size = geom.packetLength then pure ⟨pkt.data, hsize⟩
    else throw "sphinx: internal error: newNIKEPacket produced a wrong-sized packet"

/-- **`newNIKESURB`**. `keyPayload` is the recipient's own random SPRP key ‖ iv for the reply's
final payload-encryption layer (`sprpKeyMaterialLength = 64` bytes — `surb.go`'s
`io.ReadFull(r, keyPayload[:])`). Returns `(surb, decryptionKeys)`; `decryptionKeys` is exactly
what `SURB.decryptSURBPayload` wants. -/
def newNIKESURB (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (clientPrivateKey : ByteArray)
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createHeader nike macS kdfS streamS geom clientPrivateKey filler path
  -- Reverse hop order, "to ease decryption" (surb.go's comment).
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `newNIKEPacket_size`: `geom.surbLength = headerLength + nodeIDLength +
sprpKeyMaterialLength`, and `newNIKESURB`'s `surb` is exactly `hdr ++ id(32) ++
keyPayload(64)` with `hdr.size = geom.headerLength` (`createHeader`'s own loop-accumulated
invariant, the same one `newNIKEPacket_size` relies on). -/
theorem newNIKESURB_size (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry) (clientPrivateKey : ByteArray)
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (surb surbKeys : ByteArray)
    (h : newNIKESURB nike macS kdfS streamS geom clientPrivateKey keyPayload filler path
      = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength := by
  obtain ⟨-, -, -, -, -, hsurb⟩ := id hvalid
  unfold newNIKESURB at h
  dsimp only at h
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind] at h
  obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
  have hsurbeq : surb = x.1 ++ ofVector (path[0]!).id ++ ofVector keyPayload := by
    injection hfx with hfx
    exact congrArg Prod.fst hfx.symm
  have hhdrsize := createHeader_hdr_size nike macS kdfS streamS geom clientPrivateKey filler path
    x.1 x.2 hvalid hmactag hx
  rw [hsurbeq, ByteArray.size_append, ByteArray.size_append, hhdrsize, hsurb,
    CryptWalker.Util.Bytes.size_ofVector, CryptWalker.Util.Bytes.size_ofVector]
  simp only [nodeIDLength, CryptWalker.Sphinx.Constants.sprpKeyMaterialLength,
    CryptWalker.Sphinx.Constants.sprpKeyLength, CryptWalker.Sphinx.Constants.sprpIVLength,
    CryptWalker.Sphinx.Constants.streamIVLength]

/-- **`wrapNIKESURB`**: `Sphinx.Interface.newSURB` for `NIKESphinxScheme` — `newNIKESURB`, drawing
the client's ephemeral key and `keyPayload` (two seeds' worth) from the seed stream instead of
taking them as bare arguments. -/
def wrapNIKESURB (nike : NIKE) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (path : List PathHop) (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let clientKey ← nextSeed
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match newNIKESURB nike macS kdfS streamS geom (ofVector clientKey) (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    if hsize : surb.size = geom.surbLength then pure (⟨surb.data, hsize⟩, k)
    else throw "sphinx: internal error: newNIKESURB produced a wrong-sized SURB"

/-- **`unwrapNIKE`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`
(see that file). Unlike Go, a MAC mismatch reports only an error string, not also the replay
tag. -/
def unwrapNIKE (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (privKey : ByteArray) (pkt : ByteArray) :
    Except String
      (Option ByteArray × Vector UInt8 32 × List RoutingCommand × Option (Vector UInt8 pkt.size)) := do
  let geOff := 2
  let riOff := geOff + nike.publicKeySize
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  -- Dependent `if`: the size proof below needs `¬(pkt.size < payloadOff)` as a hypothesis, not
  -- just as control flow.
  if h1 : pkt.size < payloadOff then throw "sphinx: invalid packet, truncated"
  else do
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let groupElement := pkt.extract geOff riOff
  let privSk ← nikeDecodePrivateKey nike privKey
  let sharedSecret ← nikeDH nike privSk groupElement
  let replayTag := sha512_256 groupElement
  let keys := deriveHopKeys kdfS sharedSecret

  let gotMac := macS.mac (ofVector keys.headerMAC) (pkt.extract 0 macOff)
  if (ofVector gotMac).data ≠ (pkt.extract macOff (macOff + macLength)).data then
    throw "sphinx: invalid packet, MAC mismatch"

  -- Decrypt the (padding-extended) routing_info block and split off this hop's fragment.
  let mut b : ByteArray := pkt.extract riOff macOff ++ ⟨Array.replicate geom.perHopRoutingInfoLength 0⟩
  have hb : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    have hpad : (⟨Array.replicate geom.perHopRoutingInfoLength (0 : UInt8)⟩ : ByteArray).size
        = geom.perHopRoutingInfoLength := Array.size_replicate
    show (pkt.extract riOff macOff ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength
    rw [ByteArray.size_append, ByteArray.size_extract, hpad]
    omega
  b := xorBytes b (streamS.keystream (ofVector keys.headerEncryption) (ofVector keys.headerEncryptionIV) b.size)
  have hb' : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    show (xorBytes _ _).size = _
    rw [size_xorBytes]; exact hb
  let cmdBuf := b.extract 0 geom.perHopRoutingInfoLength
  let newRoutingInfo := b.extract geom.perHopRoutingInfoLength b.size
  have hnri : newRoutingInfo.size = geom.routingInfoLength := by
    show (b.extract geom.perHopRoutingInfoLength b.size).size = geom.routingInfoLength
    rw [ByteArray.size_extract]
    omega

  let cmds ← parseAll cmdBuf
  let nextNode := cmds.findSome? fun
    | .nextNodeHop id m => some (id, m)
    | _ => none
  let hasSurbReply := cmds.any fun
    | .surbReply _ => true
    | _ => false

  let rawPayload := pkt.extract payloadOff pkt.size
  have hraw : rawPayload.size = pkt.size - payloadOff := by
    show (pkt.extract payloadOff pkt.size).size = pkt.size - payloadOff
    rw [ByteArray.size_extract]
    omega
  let decPayload :=
    if rawPayload.size > 0 then cipher.decrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
    else rawPayload
  have hdec : decPayload.size = rawPayload.size := by
    show (if rawPayload.size > 0
          then cipher.decrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
          else rawPayload).size = rawPayload.size
    split
    · exact cipher.decrypt_size _ _ _
    · rfl

  match nextNode with
  | some (_nextID, nextMAC) =>
    let newGroupElement := nikeBlind nike groupElement keys.blindingFactor
    have hnewGroupElement : newGroupElement.size = nike.publicKeySize := by
      have : groupElement.size = nike.publicKeySize := by
        show (pkt.extract geOff riOff).size = nike.publicKeySize
        rw [ByteArray.size_extract]; omega
      rw [size_nikeBlind, this]
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    have hnewPayload : newPayload.size = pkt.size - payloadOff := by
      show (if decPayload.size > 0 then decPayload else rawPayload).size = pkt.size - payloadOff
      split
      · rw [hdec, hraw]
      · rw [hraw]
    let newPkt := v0AD ++ newGroupElement ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    have hnewPkt : newPkt.size = pkt.size := by
      show (v0AD ++ newGroupElement ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload).size
        = pkt.size
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          hnewGroupElement, Util.Bytes.size_ofVector, hnri, hnewPayload]
      have hv0 : v0AD.size = 2 := rfl
      have hmac : macLength = 32 := rfl
      omega
    pure (none, replayTag, cmds, some ⟨newPkt.data, hnewPkt⟩)
  | none =>
    if decPayload.size < geom.payloadTagLength then throw "sphinx: truncated payload"
    if hasSurbReply then
      pure (some decPayload, replayTag, cmds, none)
    else
      let tag := decPayload.extract 0 geom.payloadTagLength
      if !tag.data.all (· == 0) then throw "sphinx: payload auth failed"
      pure (some (decPayload.extract geom.payloadTagLength decPayload.size), replayTag, cmds, none)

set_option maxHeartbeats 1000000 in
/-- **The single-hop agreement theorem, non-terminal case.** `unwrapNIKE` applied to the packet
`hopPacket ... k` arriving at hop `k` (`k+1 < nrHops`) reproduces `hopPacket ... (k+1)` exactly,
given the receiver's private key decodes to `targetSk k` and `path[k]!` is well-formed. Beyond
the terminal case's key-agreement argument, this needs `nikeBlind_bridge` to show the receiver's
`nikeBlind groupElement keys.blindingFactor` is definitionally `telescopeElem`'s next term.
Mirrors `unwrapKEM_hopPacket_nonterminal` (simpler: no ciphertext to embed). -/
theorem unwrapNIKE_hopPacket_nonterminal (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey) (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (clientSk : nike.PrivateKey) (f targetSk : Nat → nike.PrivateKey)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hgnsize : groupElements.size = nrHops)
    (hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize)
    (hgcontent : ∀ i (_hi : i < nrHops),
        groupElements[i]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f i).1) ∧
        keys[i]! = deriveHopKeys kdfS
          (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk i) f i).1)) ∧
        nike.decodePrivateKey (toVecN nike.privateKeySize (keys[i]!).blindingFactor) = some (f i))
    (hpadsize : ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (hriKScontent : ∀ i (_hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength))
    (hriPadcontent : ∀ i (_hi : i < nrHops), riPadding[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
           ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
       else thisPad0))
    (htsize : ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (htstep : ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (hsprpkey : ∀ i (hi : i < sprpKeys.size), (sprpKeys[i]'hi).key = keys[i]!.payloadEncryption ∧
        (sprpKeys[i]'hi).iv = keys[i]!.headerEncryptionIV)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (k : Nat) (hk : k + 1 < nrHops)
    (hcmdnn : ∀ c ∈ (path[k]!).commands, c ≠ RoutingCommand.null)
    (hcmdnh : ∀ c ∈ (path[k]!).commands, ∀ id m, c ≠ RoutingCommand.nextNodeHop id m)
    (privKey : ByteArray)
    (hpp : nike.decodePrivateKey (toVecN nike.privateKeySize privKey) = some (targetSk k)) :
    ∃ (replayTag : Vector UInt8 32) (cmds : List RoutingCommand)
      (hnewsize : (hopPacket groupElements riPadding s t nrHops (k + 1)).size
        = (hopPacket groupElements riPadding s t nrHops k).size),
      unwrapNIKE nike cipher macS kdfS streamS geom privKey
          (hopPacket groupElements riPadding s t nrHops k)
        = Except.ok (none, replayTag, cmds,
            some ⟨(hopPacket groupElements riPadding s t nrHops (k + 1)).data, hnewsize⟩) ∧
      cmds = (path[k]!).commands
        ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)] := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  -- The honest NIKE key agreement at hop `k`, via `nikeDH_bridge` + `NIKE.telescope_agree`.
  obtain ⟨hgeq, hkeq, hfdecode⟩ := hgcontent k (by omega)
  have htel := telescope_agree nike clientSk (targetSk k) f k
  have hdh : nikeDH nike (targetSk k) groupElements[k]!
      = Except.ok (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk k) f k).1)) := by
    rw [hgeq, nikeDH_bridge nike (targetSk k) (telescopeElem nike clientSk f k).1
      (telescopeElem nike clientSk f k).2, htel]
  -- The loop3 trace's step at hop `k` (`j := nrHops - 1 - k`).
  have hj1 : nrHops - 1 - k < nrHops := by omega
  obtain ⟨riFragment0, hriFragment0, hR1, hM1⟩ := hstep (nrHops - 1 - k) hj1
  have hidx : nrHops - 1 - (nrHops - 1 - k) = k := by omega
  rw [hidx] at hriFragment0 hR1 hM1
  have hidx2 : nrHops - 1 - k + 1 = nrHops - k := by omega
  rw [hidx2] at hR1 hM1
  have hterm : k ≠ nrHops - 1 := by omega
  have hcond : (k == nrHops - 1) = false := by simp [hterm]
  rw [hcond] at hriFragment0
  simp only [if_false, Bool.false_eq_true] at hriFragment0
  rw [hcond] at hR1
  simp only [if_false, Bool.false_eq_true] at hR1
  set riFragmentFull := zeroPadTo geom.perHopRoutingInfoLength
    (riFragment0 ++ (RoutingCommand.nextNodeHop (path[k + 1]!).id
      (toVec32 (s (nrHops - 1 - k)).2)).toBytes) with hrfFdef
  have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - geom.nextNodeHopLength :=
    commandsToBytes_size_le hriFragment0
  have hnn : (RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)).toBytes.size
      = nextNodeHopLength := RoutingCommand.nextNodeHop_toBytes_size _ _
  have hle1 : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[k + 1]!).id
      (toVec32 (s (nrHops - 1 - k)).2)).toBytes).size ≤ geom.perHopRoutingInfoLength := by
    simp only [ByteArray.size_append, hnn]
    omega
  have hrfsize : riFragmentFull.size = geom.perHopRoutingInfoLength := zeroPadTo_size hle1
  -- Sizes needed for `cascading_xor_step`.
  have hssize := createHeader_s_size nike macS geom path keys groupElements riKeyStream riPadding
    hperhop hnnh nrHops s hstep
  have hRk1size : (s (nrHops - 1 - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
        + (nrHops - 1 - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - 1 - k) (by omega)).1
  have hprevPadsize : (if k > 0 then riPadding[k - 1]! else ByteArray.empty).size
      = k * geom.perHopRoutingInfoLength := by
    split
    · next hk0 => rw [hpadsize (k - 1) (by omega)]; congr 1; omega
    · next hk0 =>
      simp only [byteArray_empty_size]
      rw [show k = 0 from by omega, Nat.zero_mul]
  have hkssize : (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength := streamS.keystream_size _ _ _
  have hcombine : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + nrHops * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
  have hdist1 : (k + 1) * geom.perHopRoutingInfoLength
      = k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength := by ring
  have hdist2 : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + (nrHops - 1 - k) * geom.perHopRoutingInfoLength
      = (geom.nrHops - 1 - k) * geom.perHopRoutingInfoLength := by
    rw [← Nat.add_mul]; congr 1; omega
  have hkle : k * geom.perHopRoutingInfoLength ≤ geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [Nat.mul_comm geom.perHopRoutingInfoLength geom.nrHops]
    exact Nat.mul_le_mul_right _ (by omega)
  have hks_hyp : (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength)).size
      = ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
          - (k + 1) * geom.perHopRoutingInfoLength)
        + (if k > 0 then riPadding[k - 1]! else ByteArray.empty).size
        + geom.perHopRoutingInfoLength := by
    rw [hkssize, hprevPadsize, hdist1, hrouting]
    omega
  have hRk1_hyp : riFragmentFull.size + (s (nrHops - 1 - k)).1.size
      = (geom.routingInfoLength + geom.perHopRoutingInfoLength)
        - (k + 1) * geom.perHopRoutingInfoLength := by
    rw [hrfsize, hRk1size, hdist1, hdist2, hrouting, ← hcombine]
    have hdist3 : (geom.nrHops - 1 - k) * geom.perHopRoutingInfoLength
        + (k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength)
        = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
          + nrHops * geom.perHopRoutingInfoLength := by
      rw [show k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength
          = (k + 1) * geom.perHopRoutingInfoLength from by ring,
        ← Nat.add_mul, ← Nat.add_mul]
      congr 1
      omega
    omega
  have hxor := cascading_xor_step
    (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength))
    riFragmentFull (s (nrHops - 1 - k)).1 (if k > 0 then riPadding[k - 1]! else ByteArray.empty)
    ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (k + 1) * geom.perHopRoutingInfoLength)
    geom.perHopRoutingInfoLength hks_hyp hRk1_hyp
  rw [hriKScontent k (by omega)] at hR1
  set ks := streamS.keystream (ofVector keys[k]!.headerEncryption)
    (ofVector keys[k]!.headerEncryptionIV) (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    with hksdef
  set ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    - (k + 1) * geom.perHopRoutingInfoLength with hksLendef
  set prevPad := (if k > 0 then riPadding[k - 1]! else ByteArray.empty) with hprevPaddef
  set b := xorBytes ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)) ks with hbdef
  rw [← hR1] at hxor
  have hcmdBuf : b.extract 0 geom.perHopRoutingInfoLength = riFragmentFull := by
    have h1 : (b.extract 0 ksLen).extract 0 geom.perHopRoutingInfoLength
        = b.extract 0 geom.perHopRoutingInfoLength := by
      rw [ByteArray.extract_extract]
      congr 1
      omega
    rw [← h1, hxor.1, extract_append_of_le riFragmentFull _ (le_of_eq hrfsize.symm),
      ← hrfsize]
    exact ByteArray.extract_zero_size
  have hRsize : (s (nrHops - k)).1.size = ksLen := by
    rw [hR1, size_xorBytes, ByteArray.size_append]; omega
  have hRawSize : ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    simp only [ByteArray.size_append, byteArray_mk_size, Array.size_replicate]
    rw [hRsize, ← hkssize, hks_hyp]
  have hbsize : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    rw [hbdef, size_xorBytes, hRawSize]
  have hpart1 : b.extract geom.perHopRoutingInfoLength ksLen = (s (nrHops - 1 - k)).1 := by
    have h1 : (b.extract 0 ksLen).extract geom.perHopRoutingInfoLength ksLen
        = b.extract geom.perHopRoutingInfoLength ksLen := by
      rw [ByteArray.extract_extract]
      congr 1 <;> omega
    rw [← h1, hxor.1, extract_append_of_ge riFragmentFull _ (le_of_eq hrfsize)]
    rw [show geom.perHopRoutingInfoLength - riFragmentFull.size = 0 from by omega,
      show ksLen - riFragmentFull.size = (s (nrHops - 1 - k)).1.size from by omega]
    exact ByteArray.extract_zero_size
  have hpart2 : b.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
      = riPadding[k]! := by
    have heq : geom.routingInfoLength + geom.perHopRoutingInfoLength
        = ksLen + prevPad.size + geom.perHopRoutingInfoLength := by rw [← hkssize, hks_hyp]
    rw [heq, hxor.2, hkssize]
    have hpc := hriPadcontent k (by omega)
    dsimp only at hpc
    rw [← hksdef, ← hksLendef] at hpc
    generalize hthisPad0def : ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
      = thisPad0 at hpc ⊢
    by_cases hk0 : k > 0
    · rw [if_pos hk0] at hpc
      rw [hprevPaddef, if_pos hk0]
      exact hpc.symm
    · rw [if_neg hk0] at hpc
      rw [hpc, hprevPaddef, if_neg hk0]
      have hemptyxor : xorBytes (ByteArray.empty : ByteArray) ByteArray.empty = ByteArray.empty := by
        apply ByteArray.ext_getElem
        · simp
        · intro i hi hi'; simp at hi
      rw [ByteArray.size_empty, ByteArray.extract_same, hemptyxor, ByteArray.extract_zero_size,
        ByteArray.empty_append]
  have hnewRI : b.extract geom.perHopRoutingInfoLength b.size
      = (s (nrHops - 1 - k)).1 ++ riPadding[k]! := by
    rw [hbsize, ← hpart1, ← hpart2, ByteArray.extract_append_extract]
    congr 1 <;> omega
  -- The packet's own wire-format slices.
  have hslices := hopPacket_slices nike macS geom path keys groupElements riKeyStream riPadding
    sprpKeys nrHops s t hvalid hmactag hs0size hstep hgnsize hgesize hpadsize htsize ht0size
    hsprp hgen k (by omega)
  obtain ⟨hslice0, hslice1, hslice2, hslice3, hslice4⟩ := hslices
  have hpreimage : (hopPacket groupElements riPadding s t nrHops k).extract 0
      (2 + nike.publicKeySize + geom.routingInfoLength)
      = v0AD ++ groupElements[k]! ++ (s (nrHops - k)).1 ++ prevPad := by
    rw [ByteArray.extract_eq_extract_append_extract (2 + nike.publicKeySize) (by omega) (by omega),
      ByteArray.extract_eq_extract_append_extract 2 (by omega) (by omega),
      hslice0, hslice1, hslice2, ← hprevPaddef]
    simp only [ByteArray.append_assoc]
  have hgotMac : ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket groupElements riPadding s t nrHops k).extract 0
        (2 + nike.publicKeySize + geom.routingInfoLength)))
      = (s (nrHops - k)).2 := by
    rw [hpreimage]; exact hM1.symm
  have hpktsize : (hopPacket groupElements riPadding s t nrHops k).size = geom.packetLength :=
    hopPacket_size nike macS geom path keys groupElements riKeyStream riPadding sprpKeys
      nrHops s t hvalid hmactag hs0size hstep hgnsize hgesize hpadsize htsize ht0size hsprp hgen k
      (by omega)
  obtain ⟨hnnh', hperhopEq', hrouting', hheader', hpacket', -⟩ := id hvalid
  have hadL : adLength = 2 := rfl
  have hmacL : macLength = 32 := rfl
  have hpayoff : 2 + nike.publicKeySize + geom.routingInfoLength + macLength = geom.headerLength := by
    rw [hheader']; omega
  have hnottrunc : ¬ (hopPacket groupElements riPadding s t nrHops k).size
      < 2 + nike.publicKeySize + geom.routingInfoLength + macLength := by
    rw [hpktsize, hpayoff, hpacket']; omega
  unfold unwrapNIKE
  dsimp only
  rw [dif_neg hnottrunc]
  have hversion : ¬ (((hopPacket groupElements riPadding s t nrHops k).extract 0 2).data
      ≠ v0AD.data) := by rw [hslice0]; simp
  rw [if_neg hversion]
  dsimp only [Bind.bind, Except.bind]
  unfold nikeDecodePrivateKey
  rw [hpp]
  dsimp only [Bind.bind, Except.bind, pure, Except.pure]
  simp only [hslice1, hdh]
  simp only [← hkeq]
  have hmacpass : ¬ ((ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket groupElements riPadding s t nrHops k).extract 0
        (2 + nike.publicKeySize + geom.routingInfoLength)))).data
      ≠ ((hopPacket groupElements riPadding s t nrHops k).extract
          (2 + nike.publicKeySize + geom.routingInfoLength)
          (2 + nike.publicKeySize + geom.routingInfoLength + macLength)).data) := by
    rw [hgotMac, hslice3]; simp
  rw [if_neg hmacpass]
  have hle0' : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[k + 1]!).id
      (toVec32 (s (nrHops - 1 - k)).2)).toBytes).size ≤ geom.perHopRoutingInfoLength := hle1
  have hcb : commandsToBytes geom.perHopRoutingInfoLength
      ((path[k]!).commands ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id
        (toVec32 (s (nrHops - 1 - k)).2)])
      = .ok (riFragment0 ++ (RoutingCommand.nextNodeHop (path[k + 1]!).id
        (toVec32 (s (nrHops - 1 - k)).2)).toBytes) :=
    commandsToBytes_append_singleton hriFragment0 _ (by rw [hnn]; omega)
  have hcmdEq : parseAll riFragmentFull
      = Except.ok ((path[k]!).commands ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id
        (toVec32 (s (nrHops - 1 - k)).2)]) := by
    rw [hrfFdef]
    exact parseAll_commandsToBytes geom.perHopRoutingInfoLength geom.perHopRoutingInfoLength _
      (by
        intro c hc
        simp only [List.mem_append, List.mem_singleton] at hc
        rcases hc with hc | hc
        · exact hcmdnn c hc
        · rw [hc]; intro hcon; injection hcon) _ hcb hle0'
  simp only [hslice2, ← hprevPaddef, hRawSize, ← hksdef, ← hbdef, hcmdBuf, hcmdEq]
  have hfindnone : (path[k]!).commands.findSome? (fun c => match c with
      | RoutingCommand.nextNodeHop id m => some (id, m) | _ => none) = none := by
    rw [List.findSome?_eq_none_iff]
    intro c hc
    cases c with
    | nextNodeHop id m => exact absurd rfl (hcmdnh _ hc id m)
    | recipient _ => rfl
    | surbReply _ => rfl
    | nodeDelay _ => rfl
    | null => rfl
  have hnextNode : List.findSome? (fun x => match x with
      | RoutingCommand.nextNodeHop id m => some (id, m) | x => none)
      ((path[k]!).commands ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)])
      = some ((path[k + 1]!).id, toVec32 (s (nrHops - 1 - k)).2) := by
    rw [List.findSome?_append, hfindnone]
    rfl
  simp only [hnextNode]
  -- The new (re-blinded) group element: `nikeBlind`, bridged, is definitionally `telescopeElem`'s
  -- own next term.
  obtain ⟨hgeq1, -, -⟩ := hgcontent (k + 1) (by omega)
  have hnewge : nikeBlind nike groupElements[k]! keys[k]!.blindingFactor
      = groupElements[k + 1]! := by
    rw [hgeq, hgeq1]
    rw [nikeBlind_bridge nike (telescopeElem nike clientSk f k).1 (f k)
      (telescopeElem nike clientSk f k).2 keys[k]!.blindingFactor hfdecode]
    rfl
  -- The forwarded MAC.
  have hM2size : (s (nrHops - 1 - k)).2.size = 32 := by
    have hssize2 := createHeader_s_size nike macS geom path keys groupElements riKeyStream riPadding
      hperhop hnnh nrHops s hstep
    rw [(hssize2 (nrHops - 1 - k) (by omega)).2 (by omega), hmactag]
    rfl
  have hnextMac : ofVector (toVec32 (s (nrHops - 1 - k)).2) = (s (nrHops - 1 - k)).2 :=
    ofVector_toVec32 _ hM2size
  -- The payload SPRP layering: this hop peels its own outermost encryption layer.
  have hpayloadstep := newNIKEPacket_payload_content cipher sprpKeys t htstep k (by omega)
  have hsprpkeyk : sprpKeys[k]!.key = keys[k]!.payloadEncryption
      ∧ sprpKeys[k]!.iv = keys[k]!.headerEncryptionIV := by
    rw [getElem!_pos sprpKeys k (by omega)]
    exact hsprpkey k (by omega)
  rw [hsprp, hsprpkeyk.1, hsprpkeyk.2] at hpayloadstep
  have hrawsize : (t (nrHops - k)).size = geom.payloadTagLength + geom.forwardPayloadLength := by
    rw [htsize (nrHops - k) (by omega), ht0size]
  have hprevsize : (t (nrHops - 1 - k)).size = geom.payloadTagLength + geom.forwardPayloadLength := by
    rw [htsize (nrHops - 1 - k) (by omega), ht0size]
  have hnewPayload : (if
        (if ((hopPacket groupElements riPadding s t nrHops k).extract
              (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
              (hopPacket groupElements riPadding s t nrHops k).size).size > 0
          then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
            ((hopPacket groupElements riPadding s t nrHops k).extract
              (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
              (hopPacket groupElements riPadding s t nrHops k).size)
          else (hopPacket groupElements riPadding s t nrHops k).extract
            (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
            (hopPacket groupElements riPadding s t nrHops k).size).size > 0
      then
        if ((hopPacket groupElements riPadding s t nrHops k).extract
              (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
              (hopPacket groupElements riPadding s t nrHops k).size).size > 0
        then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
          ((hopPacket groupElements riPadding s t nrHops k).extract
            (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
            (hopPacket groupElements riPadding s t nrHops k).size)
        else (hopPacket groupElements riPadding s t nrHops k).extract
          (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
          (hopPacket groupElements riPadding s t nrHops k).size
      else (hopPacket groupElements riPadding s t nrHops k).extract
        (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
        (hopPacket groupElements riPadding s t nrHops k).size)
      = t (nrHops - 1 - k) := by
    rw [show nrHops - (k + 1) = nrHops - 1 - k from by omega] at hpayloadstep
    have hxsize16 : 16 ≤ (t (nrHops - 1 - k)).size := by rw [hprevsize]; omega
    have hxpos : 0 < (t (nrHops - 1 - k)).size := by omega
    have hencsize : 0 < (cipher.encrypt keys[k]!.payloadEncryption.toArray
        (ofVector keys[k]!.headerEncryptionIV) (t (nrHops - 1 - k))).size := by
      rw [cipher.encrypt_size]; omega
    simp only [hslice4, hpayloadstep]
    rw [cipher.roundTrip _ _ _ hxsize16, if_pos hencsize, if_pos hxpos]
  simp only [hnewge, hnewRI, hnextMac, hnewPayload]
  have hpktsize' : (hopPacket groupElements riPadding s t nrHops (k + 1)).size = geom.packetLength :=
    hopPacket_size nike macS geom path keys groupElements riKeyStream riPadding sprpKeys
      nrHops s t hvalid hmactag hs0size hstep hgnsize hgesize hpadsize htsize ht0size hsprp hgen (k + 1)
      (by omega)
  have hnewsize_pf : (hopPacket groupElements riPadding s t nrHops (k + 1)).size
      = (hopPacket groupElements riPadding s t nrHops k).size := by
    rw [hpktsize', hpktsize]
  have hpkteq : v0AD ++ groupElements[k + 1]! ++ ((s (nrHops - 1 - k)).1 ++ riPadding[k]!)
      ++ (s (nrHops - 1 - k)).2 ++ t (nrHops - 1 - k)
      = hopPacket groupElements riPadding s t nrHops (k + 1) := by
    unfold hopPacket
    rw [show nrHops - (k + 1) = nrHops - 1 - k from by omega, if_pos (by omega : k + 1 > 0),
      show k + 1 - 1 = k from by omega]
  refine ⟨sha512_256 groupElements[k]!,
    (path[k]!).commands ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)],
    hnewsize_pf, ?_, rfl⟩
  simp only [hpkteq]

set_option maxHeartbeats 1000000 in
/-- **The single-hop agreement theorem, terminal case.** `unwrapNIKE` applied to the packet
`hopPacket ... k` arriving at the final hop `k = nrHops - 1` reveals `payload`, given the
receiver's private key decodes to `targetSk k` and `path[k]!` is well-formed. The key agreement
is `nikeDH_bridge` composed with `NIKE.telescope_agree`: the receiver's `nikeDH (targetSk k)
groupElement` is exactly the sender's `telescopeSecret ... k`, so `deriveHopKeys` produces the
same `keys[k]!` on both sides, and everything downstream matches byte-for-byte. Mirrors
`unwrapKEM_hopPacket_terminal` (simpler: no ciphertext to carve out of the routing info). -/
theorem unwrapNIKE_hopPacket_terminal (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey) (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (clientSk : nike.PrivateKey) (f targetSk : Nat → nike.PrivateKey)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hgnsize : groupElements.size = nrHops)
    (hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize)
    (hgcontent : ∀ i (_hi : i < nrHops),
        groupElements[i]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f i).1) ∧
        keys[i]! = deriveHopKeys kdfS
          (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk i) f i).1)) ∧
        nike.decodePrivateKey (toVecN nike.privateKeySize (keys[i]!).blindingFactor) = some (f i))
    (hpadsize : ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (hriKScontent : ∀ i (_hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength))
    (htsize : ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (htstep : ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (hsprpkey : ∀ i (hi : i < sprpKeys.size), (sprpKeys[i]'hi).key = keys[i]!.payloadEncryption ∧
        (sprpKeys[i]'hi).iv = keys[i]!.headerEncryptionIV)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (k : Nat) (hk : k + 1 = nrHops)
    (hcmdnn : ∀ c ∈ (path[k]!).commands, c ≠ RoutingCommand.null)
    (hcmdnh : ∀ c ∈ (path[k]!).commands, ∀ id m, c ≠ RoutingCommand.nextNodeHop id m)
    (hcmdsurb : ∀ c ∈ (path[k]!).commands, ∀ id, c ≠ RoutingCommand.surbReply id)
    (payload : ByteArray) (hpayloadsize : payload.size = geom.forwardPayloadLength)
    (ht0content : t 0 = (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload)
    (privKey : ByteArray)
    (hpp : nike.decodePrivateKey (toVecN nike.privateKeySize privKey) = some (targetSk k)) :
    unwrapNIKE nike cipher macS kdfS streamS geom privKey
        (hopPacket groupElements riPadding s t nrHops k)
      = Except.ok (some payload, sha512_256 groupElements[k]!, (path[k]!).commands, none) := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength ≤ geom.perHopRoutingInfoLength := by omega
  -- The honest NIKE key agreement at hop `k`, via `nikeDH_bridge` + `NIKE.telescope_agree`.
  obtain ⟨hgeq, hkeq, -⟩ := hgcontent k (by omega)
  have htel := telescope_agree nike clientSk (targetSk k) f k
  have hdh : nikeDH nike (targetSk k) groupElements[k]!
      = Except.ok (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk k) f k).1)) := by
    rw [hgeq, nikeDH_bridge nike (targetSk k) (telescopeElem nike clientSk f k).1
      (telescopeElem nike clientSk f k).2, htel]
  -- The loop3 trace's step at hop `k` (`j := nrHops - 1 - k = 0`).
  have hj1 : nrHops - 1 - k < nrHops := by omega
  obtain ⟨riFragment0, hriFragment0, hR1, hM1⟩ := hstep (nrHops - 1 - k) hj1
  have hidx : nrHops - 1 - (nrHops - 1 - k) = k := by omega
  rw [hidx] at hriFragment0 hR1 hM1
  have hidx2 : nrHops - 1 - k + 1 = nrHops - k := by omega
  rw [hidx2] at hR1 hM1
  have hterm : k = nrHops - 1 := by omega
  have hcond : (k == nrHops - 1) = true := by simp [hterm]
  rw [hcond] at hriFragment0
  simp only [if_true] at hriFragment0
  rw [hcond] at hR1
  simp only [if_true] at hR1
  set riFragmentFull := zeroPadTo geom.perHopRoutingInfoLength riFragment0 with hrfFdef
  have hrfsize : riFragmentFull.size = geom.perHopRoutingInfoLength :=
    zeroPadTo_size (commandsToBytes_size_le hriFragment0)
  -- Sizes needed for `cascading_xor_step`.
  have hssize := createHeader_s_size nike macS geom path keys groupElements riKeyStream riPadding
    hperhop hnnh nrHops s hstep
  have hRk1size : (s (nrHops - 1 - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
        + (nrHops - 1 - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - 1 - k) (by omega)).1
  have hprevPadsize : (if k > 0 then riPadding[k - 1]! else ByteArray.empty).size
      = k * geom.perHopRoutingInfoLength := by
    split
    · next hk0 => rw [hpadsize (k - 1) (by omega)]; congr 1; omega
    · next hk0 =>
      simp only [byteArray_empty_size]
      rw [show k = 0 from by omega, Nat.zero_mul]
  have hkssize : (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength := streamS.keystream_size _ _ _
  have hcombine : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + nrHops * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
  have hdist1 : (k + 1) * geom.perHopRoutingInfoLength
      = k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength := by ring
  have hdist2 : (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
      + (nrHops - 1 - k) * geom.perHopRoutingInfoLength
      = (geom.nrHops - 1 - k) * geom.perHopRoutingInfoLength := by
    rw [← Nat.add_mul]; congr 1; omega
  have hkle : k * geom.perHopRoutingInfoLength ≤ geom.perHopRoutingInfoLength * geom.nrHops := by
    rw [Nat.mul_comm geom.perHopRoutingInfoLength geom.nrHops]
    exact Nat.mul_le_mul_right _ (by omega)
  have hks_hyp : (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength)).size
      = ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
          - (k + 1) * geom.perHopRoutingInfoLength)
        + (if k > 0 then riPadding[k - 1]! else ByteArray.empty).size
        + geom.perHopRoutingInfoLength := by
    rw [hkssize, hprevPadsize, hdist1, hrouting]
    omega
  have hRk1_hyp : riFragmentFull.size + (s (nrHops - 1 - k)).1.size
      = (geom.routingInfoLength + geom.perHopRoutingInfoLength)
        - (k + 1) * geom.perHopRoutingInfoLength := by
    rw [hrfsize, hRk1size, hdist1, hdist2, hrouting, ← hcombine]
    have hdist3 : (geom.nrHops - 1 - k) * geom.perHopRoutingInfoLength
        + (k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength)
        = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
          + nrHops * geom.perHopRoutingInfoLength := by
      rw [show k * geom.perHopRoutingInfoLength + geom.perHopRoutingInfoLength
          = (k + 1) * geom.perHopRoutingInfoLength from by ring,
        ← Nat.add_mul, ← Nat.add_mul]
      congr 1
      omega
    omega
  have hxor := cascading_xor_step
    (streamS.keystream (ofVector keys[k]!.headerEncryption)
      (ofVector keys[k]!.headerEncryptionIV)
      (geom.routingInfoLength + geom.perHopRoutingInfoLength))
    riFragmentFull (s (nrHops - 1 - k)).1 (if k > 0 then riPadding[k - 1]! else ByteArray.empty)
    ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (k + 1) * geom.perHopRoutingInfoLength)
    geom.perHopRoutingInfoLength hks_hyp hRk1_hyp
  rw [hriKScontent k (by omega)] at hR1
  set ks := streamS.keystream (ofVector keys[k]!.headerEncryption)
    (ofVector keys[k]!.headerEncryptionIV) (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    with hksdef
  set ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    - (k + 1) * geom.perHopRoutingInfoLength with hksLendef
  set prevPad := (if k > 0 then riPadding[k - 1]! else ByteArray.empty) with hprevPaddef
  set b := xorBytes ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)) ks with hbdef
  rw [← hR1] at hxor
  have hcmdBuf : b.extract 0 geom.perHopRoutingInfoLength = riFragmentFull := by
    have h1 : (b.extract 0 ksLen).extract 0 geom.perHopRoutingInfoLength
        = b.extract 0 geom.perHopRoutingInfoLength := by
      rw [ByteArray.extract_extract]
      congr 1
      omega
    rw [← h1, hxor.1, extract_append_of_le riFragmentFull _ (le_of_eq hrfsize.symm),
      ← hrfsize]
    exact ByteArray.extract_zero_size
  have hRsize : (s (nrHops - k)).1.size = ksLen := by
    rw [hR1, size_xorBytes, ByteArray.size_append]; omega
  have hRawSize : ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    simp only [ByteArray.size_append, byteArray_mk_size, Array.size_replicate]
    rw [hRsize, ← hkssize, hks_hyp]
  have hbsize : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    rw [hbdef, size_xorBytes, hRawSize]
  -- The packet's own wire-format slices.
  have hslices := hopPacket_slices nike macS geom path keys groupElements riKeyStream riPadding
    sprpKeys nrHops s t hvalid hmactag hs0size hstep hgnsize hgesize hpadsize htsize ht0size
    hsprp hgen k (by omega)
  obtain ⟨hslice0, hslice1, hslice2, hslice3, hslice4⟩ := hslices
  have hpreimage : (hopPacket groupElements riPadding s t nrHops k).extract 0
      (2 + nike.publicKeySize + geom.routingInfoLength)
      = v0AD ++ groupElements[k]! ++ (s (nrHops - k)).1 ++ prevPad := by
    rw [ByteArray.extract_eq_extract_append_extract (2 + nike.publicKeySize) (by omega) (by omega),
      ByteArray.extract_eq_extract_append_extract 2 (by omega) (by omega),
      hslice0, hslice1, hslice2, ← hprevPaddef]
    simp only [ByteArray.append_assoc]
  have hgotMac : ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket groupElements riPadding s t nrHops k).extract 0
        (2 + nike.publicKeySize + geom.routingInfoLength)))
      = (s (nrHops - k)).2 := by
    rw [hpreimage]; exact hM1.symm
  have hpktsize : (hopPacket groupElements riPadding s t nrHops k).size = geom.packetLength :=
    hopPacket_size nike macS geom path keys groupElements riKeyStream riPadding sprpKeys
      nrHops s t hvalid hmactag hs0size hstep hgnsize hgesize hpadsize htsize ht0size hsprp hgen k
      (by omega)
  obtain ⟨hnnh', hperhopEq', hrouting', hheader', hpacket', -⟩ := id hvalid
  have hadL : adLength = 2 := rfl
  have hmacL : macLength = 32 := rfl
  have hpayoff : 2 + nike.publicKeySize + geom.routingInfoLength + macLength = geom.headerLength := by
    rw [hheader']; omega
  have hnottrunc : ¬ (hopPacket groupElements riPadding s t nrHops k).size
      < 2 + nike.publicKeySize + geom.routingInfoLength + macLength := by
    rw [hpktsize, hpayoff, hpacket']; omega
  unfold unwrapNIKE
  dsimp only
  rw [dif_neg hnottrunc]
  have hversion : ¬ (((hopPacket groupElements riPadding s t nrHops k).extract 0 2).data
      ≠ v0AD.data) := by rw [hslice0]; simp
  rw [if_neg hversion]
  dsimp only [Bind.bind, Except.bind]
  unfold nikeDecodePrivateKey
  rw [hpp]
  dsimp only [Bind.bind, Except.bind, pure, Except.pure]
  simp only [hslice1, hdh]
  simp only [← hkeq]
  have hmacpass : ¬ ((ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket groupElements riPadding s t nrHops k).extract 0
        (2 + nike.publicKeySize + geom.routingInfoLength)))).data
      ≠ ((hopPacket groupElements riPadding s t nrHops k).extract
          (2 + nike.publicKeySize + geom.routingInfoLength)
          (2 + nike.publicKeySize + geom.routingInfoLength + macLength)).data) := by
    rw [hgotMac, hslice3]; simp
  rw [if_neg hmacpass]
  have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength := commandsToBytes_size_le hriFragment0
  have hcmdEq : parseAll riFragmentFull = Except.ok (path[k]!).commands := by
    rw [hrfFdef]
    exact parseAll_commandsToBytes geom.perHopRoutingInfoLength geom.perHopRoutingInfoLength
      (path[k]!).commands hcmdnn riFragment0 hriFragment0 hle0
  simp only [hslice2, ← hprevPaddef, hRawSize, ← hksdef, ← hbdef, hcmdBuf, hcmdEq]
  have hfindnone : (path[k]!).commands.findSome? (fun c => match c with
      | RoutingCommand.nextNodeHop id m => some (id, m) | _ => none) = none := by
    rw [List.findSome?_eq_none_iff]
    intro c hc
    cases c with
    | nextNodeHop id m => exact absurd rfl (hcmdnh _ hc id m)
    | recipient _ => rfl
    | surbReply _ => rfl
    | nodeDelay _ => rfl
    | null => rfl
  have hnosurb : (path[k]!).commands.any (fun c => match c with
      | RoutingCommand.surbReply _ => true | _ => false) = false := by
    rw [List.any_eq_false]
    intro c hc
    cases c with
    | nextNodeHop _ _ => simp
    | recipient _ => simp
    | surbReply id => exact absurd rfl (hcmdsurb _ hc id)
    | nodeDelay _ => simp
    | null => simp
  simp only [hfindnone, hnosurb]
  -- The payload SPRP layering: the terminal hop peels its last encryption layer, exposing `t 0`.
  have hpayloadstep := newNIKEPacket_payload_content cipher sprpKeys t htstep k (by omega)
  have hsprpkeyk : sprpKeys[k]!.key = keys[k]!.payloadEncryption
      ∧ sprpKeys[k]!.iv = keys[k]!.headerEncryptionIV := by
    rw [getElem!_pos sprpKeys k (by omega)]
    exact hsprpkey k (by omega)
  rw [hsprp, hsprpkeyk.1, hsprpkeyk.2] at hpayloadstep
  rw [show nrHops - (k + 1) = 0 from by omega] at hpayloadstep
  have ht1size : (t (nrHops - k)).size = geom.payloadTagLength + geom.forwardPayloadLength := by
    rw [htsize (nrHops - k) (by omega), ht0size]
  have hx0size16 : 16 ≤ (t 0).size := by rw [ht0size]; omega
  have hdecEq : cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
      (t (nrHops - k)) = t 0 := by
    rw [hpayloadstep, cipher.roundTrip _ _ _ hx0size16]
  have hpos1 : 0 < (t (nrHops - k)).size := by rw [ht1size]; omega
  have hdecPayloadEq : (if ((hopPacket groupElements riPadding s t nrHops k).extract
        (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
        (hopPacket groupElements riPadding s t nrHops k).size).size > 0
      then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
        ((hopPacket groupElements riPadding s t nrHops k).extract
          (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
          (hopPacket groupElements riPadding s t nrHops k).size)
      else (hopPacket groupElements riPadding s t nrHops k).extract
        (2 + nike.publicKeySize + geom.routingInfoLength + macLength)
        (hopPacket groupElements riPadding s t nrHops k).size) = t 0 := by
    rw [hslice4, if_pos hpos1, hdecEq]
  simp only [hdecPayloadEq, ht0content]
  have htagsize : (⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray).size
      = geom.payloadTagLength := Array.size_replicate
  have htruncFalse : ¬ (((⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray)
      ++ payload).size < geom.payloadTagLength) := by
    rw [ByteArray.size_append, htagsize, hpayloadsize]; omega
  rw [if_neg htruncFalse]
  have htagEq : ((⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray)
      ++ payload).extract 0 geom.payloadTagLength
      = (⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray) := by
    have h := extract_append_left (⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray) payload
    rwa [htagsize] at h
  have htagAllZero : ¬ (!(((⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray)
      ++ payload).extract 0 geom.payloadTagLength).data.all (· == 0)) = true := by
    rw [htagEq]
    simp only [Bool.not_eq_true, Bool.not_eq_false']
    rw [Array.all_eq_true]
    intro i hi
    simp [Array.getElem_replicate]
  rw [if_neg htagAllZero]
  have hpayloadEq : ((⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray)
      ++ payload).extract geom.payloadTagLength
      (((⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray) ++ payload)).size
      = payload := by
    rw [ByteArray.size_append, htagsize]
    have := extract_append_right (⟨Array.replicate geom.payloadTagLength (0 : UInt8)⟩ : ByteArray) payload
    rwa [htagsize] at this
  simp only [hpayloadEq, Bool.false_eq_true, if_false]

set_option maxHeartbeats 1000000 in
/-- **The multi-hop completeness induction.** Starting `unwrapChainAux` at any hop `k < nrHops` on
`hopPacket ... k`, given the remaining `nrHops - k` private keys each decoding to `targetSk
(k+i)`, always recovers `payload` — downward induction on `privKeys`, repeatedly applying
`unwrapNIKE_hopPacket_nonterminal` to peel one hop until `unwrapNIKE_hopPacket_terminal` closes
the last one. Mirrors `unwrapChain_hopPacket` on the KEM side. -/
theorem unwrapChain_hopPacket (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (groupElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey) (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (clientSk : nike.PrivateKey) (f targetSk : Nat → nike.PrivateKey)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
    (hstep : ∀ j (_hj : j < nrHops), ∃ riFragment0,
        commandsToBytes
          (if (nrHops - 1 - j) == nrHops - 1 then geom.perHopRoutingInfoLength
           else geom.perHopRoutingInfoLength - geom.nextNodeHopLength)
          (path[nrHops - 1 - j]!).commands = Except.ok riFragment0 ∧
        (s (j + 1)).1 = xorBytes (zeroPadTo geom.perHopRoutingInfoLength
            (if (nrHops - 1 - j) == nrHops - 1 then riFragment0
             else riFragment0 ++ (RoutingCommand.nextNodeHop (path[nrHops - 1 - j + 1]!).id
               (toVec32 (s j).2)).toBytes) ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ groupElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hgnsize : groupElements.size = nrHops)
    (hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize)
    (hgcontent : ∀ i (_hi : i < nrHops),
        groupElements[i]! = ofVector (nike.encodePublicKey (telescopeElem nike clientSk f i).1) ∧
        keys[i]! = deriveHopKeys kdfS
          (ofVector (nike.encodeSharedSecret (telescopeSecret nike clientSk (targetSk i) f i).1)) ∧
        nike.decodePrivateKey (toVecN nike.privateKeySize (keys[i]!).blindingFactor) = some (f i))
    (hpadsize : ∀ i (_hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (hriKScontent : ∀ i (_hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength))
    (hriPadcontent : ∀ i (_hi : i < nrHops), riPadding[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
           ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
       else thisPad0))
    (htsize : ∀ j (_hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (htstep : ∀ j (_hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (hsprpkey : ∀ i (hi : i < sprpKeys.size), (sprpKeys[i]'hi).key = keys[i]!.payloadEncryption ∧
        (sprpKeys[i]'hi).iv = keys[i]!.headerEncryptionIV)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (hcmdnn : ∀ i (_hi : i < nrHops), ∀ c ∈ (path[i]!).commands, c ≠ RoutingCommand.null)
    (hcmdnh : ∀ i (_hi : i < nrHops), ∀ c ∈ (path[i]!).commands, ∀ id m, c ≠ RoutingCommand.nextNodeHop id m)
    (hcmdsurb : ∀ c ∈ (path[nrHops - 1]!).commands, ∀ id, c ≠ RoutingCommand.surbReply id)
    (payload : ByteArray) (hpayloadsize : payload.size = geom.forwardPayloadLength)
    (ht0content : t 0 = (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload) :
    ∀ (k : Nat) (privKeys : List ByteArray) (_hk : k < nrHops)
      (_hprivlen : privKeys.length = nrHops - k)
      (_hpp : ∀ i (_hi : i < privKeys.length),
        nike.decodePrivateKey (toVecN nike.privateKeySize privKeys[i]!) = some (targetSk (k + i))),
      unwrapChainAux (unwrapNIKE nike cipher macS kdfS streamS geom) privKeys
          (hopPacket groupElements riPadding s t nrHops k)
        = Except.ok (some payload) := by
  intro k privKeys
  induction privKeys generalizing k with
  | nil => intro hk hprivlen _; simp only [List.length_nil] at hprivlen; omega
  | cons sk rest ih =>
    intro hk hprivlen hpp
    have hpp0 : nike.decodePrivateKey (toVecN nike.privateKeySize sk) = some (targetSk k) := by
      have h0 := hpp 0 (by simp)
      rwa [List.getElem!_cons_zero, show k + 0 = k from by omega] at h0
    unfold unwrapChainAux
    dsimp only
    by_cases hterm : k + 1 = nrHops
    · rw [unwrapNIKE_hopPacket_terminal nike cipher macS kdfS streamS geom path keys groupElements
        riKeyStream riPadding sprpKeys nrHops s t clientSk f targetSk hvalid hmactag hs0size hstep
        hgnsize hgesize hgcontent hpadsize hriKScontent htsize ht0size htstep hsprpkey hsprp hgen
        h16 k hterm (hcmdnn k hk) (hcmdnh k hk)
        (by rw [show k = nrHops - 1 from by omega]; exact hcmdsurb)
        payload hpayloadsize ht0content sk hpp0]
      dsimp only [Bind.bind, Except.bind]
      rfl
    · have hklt : k + 1 < nrHops := by omega
      obtain ⟨replayTag, cmds, hnewsize, heq, hcmdseq⟩ := unwrapNIKE_hopPacket_nonterminal nike cipher
        macS kdfS streamS geom path keys groupElements riKeyStream riPadding sprpKeys nrHops s t
        clientSk f targetSk hvalid hmactag hs0size hstep hgnsize hgesize hgcontent hpadsize
        hriKScontent hriPadcontent htsize ht0size htstep hsprpkey hsprp hgen h16 k hklt
        (hcmdnn k (by omega)) (hcmdnh k (by omega)) sk hpp0
      rw [heq]
      dsimp only [Bind.bind, Except.bind]
      have hrestlen : rest.length = nrHops - (k + 1) := by
        simp only [List.length_cons] at hprivlen; omega
      have hrest : ∀ i (hi : i < rest.length),
          nike.decodePrivateKey (toVecN nike.privateKeySize rest[i]!) = some (targetSk ((k + 1) + i)) := by
        intro i hi
        have hi' := hpp (i + 1) (by simp only [List.length_cons]; omega)
        rw [List.getElem!_cons_succ] at hi'
        rwa [show k + (i + 1) = k + 1 + i from by omega] at hi'
      have hind := ih (k + 1) hklt hrestlen hrest
      have hofv : ofVector (⟨(hopPacket groupElements riPadding s t nrHops (k + 1)).data, hnewsize⟩ :
          Vector UInt8 (hopPacket groupElements riPadding s t nrHops k).size)
          = hopPacket groupElements riPadding s t nrHops (k + 1) := rfl
      rw [hofv]
      exact hind

private theorem wrapNIKE_bytesPub (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (path : List PathHop)
    (filler : ByteArray) (payload : Vector UInt8 geom.forwardPayloadLength) (i : Nat)
    (str : Nat → Vector UInt8 32) (v : Vector UInt8 geom.packetLength) (s' : SeedStream)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (h : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str) = .ok v s') :
    (ofVector v).extract 2 (2 + nike.publicKeySize) = nikeSelfPublicKeyBytes nike (ofVector (str i)) := by
  rcases hX : newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler
      path.toArray (ofVector payload) with e | raw
  · have hw : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str)
        = .error e (i + 1, str) := by
      simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
      match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
          (ofVector payload), hX with
      | _, rfl => rfl
    rw [hw] at h; injection h
  · have hsize := newNIKEPacket_size nike cipher macS kdfS streamS geom (ofVector (str i)) filler
      path.toArray (ofVector payload) raw hvalid hmactag hX (by simp)
    have hw : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str)
        = .ok ⟨raw.data, hsize⟩ (i + 1, str) := by
      simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
      match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
          (ofVector payload), hX with
      | _, rfl => simp [dif_pos hsize, EStateM.pure, pure]
    rw [hw] at h
    injection h with h
    rw [← h]
    exact newNIKEPacket_bytesPub nike cipher macS kdfS streamS geom (ofVector (str i)) filler
      path.toArray (ofVector payload) raw hX

/-- Envelope bytes are a pure function of the seed drawn from `state` (`createHeader`'s
`groupElements[0]!`, never overwritten after `Array.replicate`), regardless of the path/filler/
payload the rest of `wrap` is building. -/
theorem wrapNIKE_envelope_indep (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (hop0 hop1 : PathHop)
    (rest0 rest1 : List PathHop) (filler0 filler1 : ByteArray)
    (payload0 payload1 : Vector UInt8 geom.forwardPayloadLength)
    (st : SeedStream) (pkt0 pkt1 : Vector UInt8 geom.packetLength) (st0' st1' : SeedStream)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength) :
    wrapNIKE nike cipher macS kdfS streamS geom (hop0 :: rest0) filler0 payload0 st = .ok pkt0 st0' →
    wrapNIKE nike cipher macS kdfS streamS geom (hop1 :: rest1) filler1 payload1 st = .ok pkt1 st1' →
    (ofVector pkt0).extract 2 (2 + nike.publicKeySize) = (ofVector pkt1).extract 2 (2 + nike.publicKeySize) := by
  intro h0 h1
  obtain ⟨i, str⟩ := st
  rw [wrapNIKE_bytesPub nike cipher macS kdfS streamS geom (hop0 :: rest0) filler0 payload0 i str
      pkt0 st0' hvalid hmactag h0,
    wrapNIKE_bytesPub nike cipher macS kdfS streamS geom (hop1 :: rest1) filler1 payload1 i str
      pkt1 st1' hvalid hmactag h1]

/-- **`wrapNIKE`, fully unfolded to content.** A successful `wrapNIKE` run drew one seed (via
`nextSeed`, which never fails) and then `newNIKEPacket` succeeded on it, producing exactly `pkt`'s
own bytes. Mirrors `KEMSphinx.wrapKEM_unfold` (simpler: `wrapNIKE` draws a single client-key seed,
not an array of per-hop seeds). -/
private theorem wrapNIKE_unfold (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (i : Nat) (str : Nat → Vector UInt8 32)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream)
    (h : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str) = .ok pkt st') :
    newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
      (ofVector payload) = Except.ok (ofVector pkt) := by
  rcases hX : newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler
      path.toArray (ofVector payload) with e | raw
  · exfalso
    have hw : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str)
        = .error e (i + 1, str) := by
      simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
      match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
          (ofVector payload), hX with
      | _, rfl => rfl
    rw [hw] at h; injection h
  · by_cases hsz : raw.size = geom.packetLength
    · have hw : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str)
          = .ok ⟨raw.data, hsz⟩ (i + 1, str) := by
        simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
        match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
            (ofVector payload), hX with
        | _, rfl => simp [dif_pos hsz, EStateM.pure, pure]
      rw [hw] at h
      injection h with h
      congr 1
      rw [← h]
      rfl
    · exfalso
      have hw : wrapNIKE nike cipher macS kdfS streamS geom path filler payload (i, str)
          = .error "sphinx: internal error: newNIKEPacket produced a wrong-sized packet"
            (i + 1, str) := by
        simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
        match newNIKEPacket nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
            (ofVector payload), hX with
        | _, rfl => dsimp only; rw [dif_neg hsz]; rfl
      rw [hw] at h; injection h

/-- **The real completeness theorem**: `NIKESphinxScheme`'s witness for
`Sphinx.Interface.unwrap_complete`, proved outright, generic over the wide-block cipher/MAC/KDF/
stream cipher (mirrors `wrapKEM_unwrapKEM_complete_valid`). `targetSk i` is `privKeys[i]!`'s own
decoded private key, never an independently-chosen "honest" secret — this is what lets the
key-agreement argument go through with no `derivePublicKey`-injectivity assumption: the receiver
at hop `i` simply uses the secret `hpriv` already says its own public key matches. -/
theorem wrapNIKE_unwrapNIKE_complete_valid (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (hvalid : geom.ValidForNIKE nike)
    (hmactag : macS.tagSize = macLength) (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (path : List PathHop) (privKeys : List ByteArray) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream)
    (hpath : path ≠ [])
    (hpriv : path.map (·.publicKey) = privKeys.map (nikeSelfPublicKeyBytes nike))
    (hcmds : ∀ hop ∈ path, ∀ c ∈ hop.commands, c ≠ .null ∧ (∀ id m, c ≠ .nextNodeHop id m))
    (hsurb : ∀ c ∈ (path[path.length - 1]!).commands, ∀ id, c ≠ .surbReply id)
    (hwrap : wrapNIKE nike cipher macS kdfS streamS geom path filler payload st = .ok pkt st') :
    unwrapChainAux (unwrapNIKE nike cipher macS kdfS streamS geom) privKeys (ofVector pkt)
      = .ok (some (ofVector payload)) := by
  obtain ⟨i, str⟩ := st
  have hnk := wrapNIKE_unfold nike cipher macS kdfS streamS geom path filler payload i str pkt st' hwrap
  obtain ⟨hpaysize, hdr, sprpKeys, t, hcreate, ht0content, htstep, hpkteq⟩ :=
    newNIKEPacket_unfold nike cipher macS kdfS streamS geom (ofVector (str i)) filler path.toArray
      (ofVector payload) (ofVector pkt) hnk
  have hlen : path.length = privKeys.length := by
    have := congrArg List.length hpriv
    simpa using this
  -- `targetSk i` is `privKeys[i]!`'s own decoded private key.
  let targetSk : Nat → nike.PrivateKey := fun i =>
    (nike.decodePrivateKey_total (toVecN nike.privateKeySize privKeys[i]!)).choose
  have htargetSk : ∀ i, nike.decodePrivateKey (toVecN nike.privateKeySize privKeys[i]!) = some (targetSk i) :=
    fun i => (nike.decodePrivateKey_total (toVecN nike.privateKeySize privKeys[i]!)).choose_spec
  have htarget : ∀ j (hj : j < path.toArray.size), (path.toArray[j]!).publicKey
      = ofVector (nike.encodePublicKey (nike.derivePublicKey (targetSk j))) := by
    intro j hj
    have hj' : j < path.length := by rwa [← List.size_toArray]
    have hjp : j < privKeys.length := by rw [← hlen]; exact hj'
    have hcL : (path.map (·.publicKey))[j]'(by simpa using hj')
        = (privKeys.map (nikeSelfPublicKeyBytes nike))[j]'(by simpa using hjp) := by
      simp only [hpriv]
    rw [List.getElem_map, List.getElem_map] at hcL
    rw [List.getElem!_toArray, getElem!_pos path j hj', hcL, ← getElem!_pos privKeys j hjp]
    unfold nikeSelfPublicKeyBytes
    rw [htargetSk j]
  obtain ⟨hpne, hgen, hfsize, clientSk, f, groupElements, keys, riKeyStream, riPadding, s,
    hgsize, hksize, hriKSsize, hriPadArrSize, hself, hgcontent, hriContent, hs0eq, hstep, hhdreq,
    hsprpeq⟩ :=
    createHeader_unfold nike macS kdfS streamS geom (ofVector (str i)) filler path.toArray hdr
      sprpKeys hcreate targetSk htarget
  set nrHops := path.toArray.size with hnrHopsdef
  have hgen' : nrHops ≤ geom.nrHops := hgen
  have hsprp : sprpKeys.size = nrHops := by rw [hsprpeq]; simp
  have hgesize : ∀ j (hj : j < groupElements.size), (groupElements[j]'hj).size = nike.publicKeySize := by
    intro j hj
    have hj' : j < nrHops := by rwa [hgsize] at hj
    rw [← getElem!_pos groupElements j hj, (hgcontent j hj').1]
    exact Util.Bytes.size_ofVector _
  have hriKScontent : ∀ i (hi : i < nrHops), riKeyStream[i]! =
      (streamS.keystream (ofVector (keys[i]!).headerEncryption) (ofVector (keys[i]!).headerEncryptionIV)
          (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
        ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (i + 1) * geom.perHopRoutingInfoLength) :=
    fun i hi => (hriContent i hi).1
  have hriPadcontent : ∀ i (hi : i < nrHops), riPadding[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
           ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
       else thisPad0) :=
    fun i hi => (hriContent i hi).2
  have hle : ∀ j (hj : j < nrHops), (j + 1) * geom.perHopRoutingInfoLength
      ≤ geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    intro j hj
    obtain ⟨-, -, hrouting, -, -, -⟩ := id hvalid
    rw [hrouting]
    have h1 : (j + 1) * geom.perHopRoutingInfoLength ≤ geom.perHopRoutingInfoLength * geom.nrHops := by
      rw [Nat.mul_comm geom.perHopRoutingInfoLength geom.nrHops]
      exact Nat.mul_le_mul_right _ (by omega)
    omega
  have hpadsize := createHeader_loop2_padsize_of_content streamS geom keys nrHops riKeyStream
    riPadding hriContent hle
  have hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength := by
    rw [hs0eq]
    split
    · next hc => rw [hfsize hc]
    · next hc =>
      simp only [byteArray_empty_size]
      have heq : geom.nrHops - nrHops = 0 := by omega
      rw [heq, Nat.zero_mul]
  have ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength := by
    rw [ht0content, ByteArray.size_append, byteArray_mk_size, Array.size_replicate,
      Util.Bytes.size_ofVector]
  have hsprpkey : ∀ i (hi : i < sprpKeys.size), (sprpKeys[i]'hi).key = keys[i]!.payloadEncryption ∧
      (sprpKeys[i]'hi).iv = keys[i]!.headerEncryptionIV := by
    intro i hi
    simp only [hsprpeq, Array.getElem_ofFn]
    trivial
  have hcmdnn : ∀ i (hi : i < nrHops), ∀ c ∈ (path.toArray[i]!).commands, c ≠ RoutingCommand.null := by
    intro i hi c hc
    rw [List.getElem!_toArray] at hc
    have hi' : i < path.length := by rwa [← List.size_toArray]
    have hmem : path[i]! ∈ path := by rw [getElem!_pos path i hi']; exact List.getElem_mem hi'
    exact (hcmds path[i]! hmem c hc).1
  have hcmdnh : ∀ i (hi : i < nrHops), ∀ c ∈ (path.toArray[i]!).commands,
      ∀ id m, c ≠ RoutingCommand.nextNodeHop id m := by
    intro i hi c hc id m
    rw [List.getElem!_toArray] at hc
    have hi' : i < path.length := by rwa [← List.size_toArray]
    have hmem : path[i]! ∈ path := by rw [getElem!_pos path i hi']; exact List.getElem_mem hi'
    exact (hcmds path[i]! hmem c hc).2 id m
  have hnrHopseq : nrHops = path.length := hnrHopsdef.trans List.size_toArray
  have hcmdsurb : ∀ c ∈ (path.toArray[nrHops - 1]!).commands, ∀ id, c ≠ RoutingCommand.surbReply id := by
    intro c hc id
    rw [List.getElem!_toArray, hnrHopseq] at hc
    exact hsurb c hc id
  have hnrpos : 0 < nrHops := by
    rw [hnrHopsdef, List.size_toArray]
    exact List.length_pos_of_ne_nil hpath
  have htsize := newNIKEPacket_payload_size_trace cipher sprpKeys t htstep
  have hind := unwrapChain_hopPacket nike cipher macS kdfS streamS geom path.toArray keys
    groupElements riKeyStream riPadding sprpKeys nrHops s t clientSk f targetSk hvalid hmactag
    hs0size hstep hgsize hgesize hgcontent hpadsize hriKScontent hriPadcontent htsize ht0size
    htstep hsprpkey hsprp hgen' h16 hcmdnn hcmdnh hcmdsurb (ofVector payload)
    (Util.Bytes.size_ofVector _) ht0content
    0 privKeys hnrpos (by omega)
    (fun i hi => by rw [Nat.zero_add]; exact htargetSk i)
  have hpkteq2 : ofVector pkt = hopPacket groupElements riPadding s t nrHops 0 := by
    rw [hpkteq, hhdreq]
    unfold hopPacket
    have h0 : nrHops - 0 = nrHops := by omega
    rw [h0, if_neg (lt_irrefl 0), ByteArray.append_empty, hsprp]
  rw [hpkteq2]
  exact hind

/-- The base `Sphinx.Interface.Sphinx` instance for `nike` — everything `nikeSphinxSchemeOf`
provides except the re-blindable-envelope structure, which needs a `Fintype`/`SampleableType`
instance for `nike.PrivateKey` only classical choice can supply for an arbitrary runtime `NIKE`.
This core needs none of that, so unlike `nikeSphinxSchemeOf`/`nikeSphinxScheme` it compiles to
real code — executable callers (tests, vector generation) should use this. -/
def nikeSphinxCore (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (hvalid : geom.ValidForNIKE nike)
    (hmactag : macS.tagSize = macLength)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) :
    CryptWalker.Sphinx.Interface.Sphinx where
  State := SeedStream
  PrivateKey := ByteArray
  Command := RoutingCommand
  geometry := geom
  stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
  cipher := cipher
  mac    := macS
  kdf    := kdfS
  stream := streamS
  derivePublicKey := nikeSelfPublicKeyBytes nike
  wrap := wrapNIKE nike cipher macS kdfS streamS geom
  unwrap := unwrapNIKE nike cipher macS kdfS streamS geom
  newSURB := wrapNIKESURB nike macS kdfS streamS geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB cipher geom (ofVector surb) payload
  unwrap_complete := fun path privKeys filler payload st pkt st' hpath hkeys hcmds hsurb hwrap =>
    wrapNIKE_unwrapNIKE_complete_valid nike cipher macS kdfS streamS geom hvalid hmactag h16
      path privKeys filler payload st pkt st' hpath hkeys hcmds hsurb hwrap

/-- Build a `NIKESphinxScheme` from any `NIKE` at all — total, no `Except`, since every field here
is defined unconditionally (needed by test/vector-generation code, which can't route through
`nikeSphinxScheme`'s `Except` return because `NIKESphinxScheme` has `Type`-valued fields, putting it
in `Type 1`, which `IO.ofExcept` cannot hold). `noncomputable` — see `nikeSphinxCore`'s doc comment
if only the base `Sphinx` fields are actually needed. -/
noncomputable def nikeSphinxSchemeOf (nike : NIKE) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (hvalid : geom.ValidForNIKE nike) (hmactag : macS.tagSize = macLength)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) : NIKESphinxScheme where
  toSphinx := nikeSphinxCore nike cipher macS kdfS streamS geom hvalid hmactag h16
  Envelope := nike.PublicKey
  parseEnvelope := fun pkt =>
    (nike.decodePublicKey (toVecN nike.publicKeySize ((ofVector pkt).extract 2 (2 + nike.publicKeySize)))).getD default
  Factor := nike.PrivateKey
  blind := nikeBlindTyped nike
  envelope_indep := fun hop0 hop1 rest0 rest1 filler0 filler1 payload0 payload1 st pkt0 pkt1
      st0' st1' h0 h1 =>
    congrArg (fun b => (nike.decodePublicKey (toVecN nike.publicKeySize b)).getD default)
      (wrapNIKE_envelope_indep nike cipher macS kdfS streamS geom hop0 hop1 rest0 rest1 filler0
        filler1 payload0 payload1 st pkt0 pkt1 st0' st1' hvalid hmactag h0 h1)
  nike := nike

/-- Build a `NIKESphinxScheme` for whatever NIKE `geom.scheme` names, resolved through
`CryptWalker.NIKE.byName` — the same registry `Geometry.ofNIKE` resolves against. Registering a
new NIKE needs no change here. Checks `geom.ValidForNIKE nike` (decidable), rejecting a mismatched
`geom` explicitly rather than trusting it silently.

The one place that picks a concrete cryptographic stack (AEZ/HMAC-SHA256/HKDF-SHA256-Expand/
AES-256-CTR, matching `sphinx_nike_vectors.json`) — `nikeSphinxSchemeOf` underneath is fully
generic, this is just the default a caller who only knows a NIKE's name needs. -/
noncomputable def nikeSphinxScheme (geom : Geometry) : Except String NIKESphinxScheme :=
  match geom.scheme with
  | .inr name => throw s!"sphinx: geometry scheme {name} is a KEM, not a NIKE"
  | .inl name =>
    match CryptWalker.NIKE.byName name with
    | none => throw s!"sphinx: NIKE scheme {name} not implemented"
    | some nike =>
      if hvalid : geom.ValidForNIKE nike then
        if hmactag : CryptWalker.MAC.HMAC.hmacSha256MAC.tagSize = macLength then
          if h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength then
            pure (nikeSphinxSchemeOf nike CryptWalker.WideBlockCipher.AEZ.aez
              CryptWalker.MAC.HMAC.hmacSha256MAC
              CryptWalker.KDF.HKDF.hkdfSha256Expand
              CryptWalker.StreamCipher.AES256CTR.aes256CTR geom hvalid hmactag h16)
          else throw s!"sphinx: geometry's payload tag/forward payload too short for scheme {name}"
        else throw "sphinx: internal error: hmacSha256MAC.tagSize ≠ macLength"
      else throw s!"sphinx: geometry is not valid for NIKE scheme {name}"


end CryptWalker.Sphinx.NIKESphinx
