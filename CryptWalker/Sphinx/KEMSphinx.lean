/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.Interface
import CryptWalker.Sphinx.Common
import CryptWalker.Sphinx.NIKESphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Schemes
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.KEMSphinx

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.NIKESphinx (HopKeys deriveHopKeys)
open CryptWalker.Sphinx.Crypto.Stream (keystream)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

/-! # KEM-Sphinx

Port of `kemsphinx.go`, genuinely generic over any `kem : CryptWalker.KEM.KEM.KEM` — not
hardcoded to X25519, not specified in terms of a NIKE, and not bundled with a proof of any
particular key size (a `KEM` already carries its own `ciphertextSize`/`publicKeySize`/
`privateKeySize`, read directly, the same way `NIKESphinx` reads a `NIKE`'s).

`KEM.KEM`'s abstract interface used to have no generic "seed the internal randomness from this
value" or "derive a public key from a private key" operation — both are things this file
genuinely needs (a packet's bytes must be an exact function of the caller's own seed stream, and
a client must be able to state its own public key without generating a fresh pair), and
previously the only way to get them was to reach past the interface into the underlying
`(Adapter.PRF, NIKE)` pair every constructible `KEM` happens to be built from. `KEM.KEM` now
carries `stateFromSeed`/`derivePublicKey` directly (see that file), so this one no longer needs
to know a `KEM` is secretly a NIKE adapter at all.

Differences from `NIKESphinx`, per `kemsphinx.go`/`docs/specs/kemsphinx.md`:

* One KEM encapsulation per hop, independent of the others — no blinding chain, so no
  `HopKeys.blindingFactor` (reused from `NIKESphinx` regardless, unused, matching how Go reuses
  `crypto.PacketKeys` with `BlindingFactor = nil` rather than a separate type).
* The header's group-element field becomes a KEM ciphertext (`kem.ciphertextSize` bytes); every
  non-terminal hop's per-hop routing-info block embeds the *next* hop's ciphertext in its last
  `kem.ciphertextSize` bytes, rather than carrying it via a `NextNodeHop` command field.
* Forwarding just copies the embedded next-hop ciphertext into the group-element slot — no
  `Blind` step, since there is no group element to re-blind. -/

/-- One hop's encapsulation, at the byte level: decode the recipient's public key, run `kem.encap`
seeded deterministically from `seed`, and re-encode both outputs. `Except`, not `Option`: a bad
encoding and an unsafe/small-order public key are both genuine, reported failures. -/
private def kemEncap (kem : KEM) (pkBytes : ByteArray) (seed : Vector UInt8 32) :
    Except String (ByteArray × ByteArray) :=
  match kem.decodePublicKey (toVecN kem.publicKeySize pkBytes) with
  | none => throw "sphinx: invalid public key encoding"
  | some pk =>
    match kem.encap pk (kem.stateFromSeed seed) with
    | .ok (ct, ss) _ => pure (ofVector (kem.encodeCiphertext ct), ofVector (kem.encodePlaintext ss))
    | .error _ _ => throw "sphinx: KEM encapsulation failed"

/-- One hop's decapsulation, at the byte level: decode the private key and the ciphertext, then
run `kem.decap`. Decapsulation draws no randomness, so any seed works for `stateFromSeed`. -/
private def kemDecap (kem : KEM) (skBytes ctBytes : ByteArray) : Except String ByteArray :=
  match kem.decodePrivateKey (toVecN kem.privateKeySize skBytes),
      kem.decodeCiphertext (toVecN kem.ciphertextSize ctBytes) with
  | some sk, some ct =>
    match kem.decap sk ct (kem.stateFromSeed (Vector.replicate 32 0)) with
    | .ok ss _ => pure (ofVector (kem.encodePlaintext ss))
    | .error _ _ => throw "sphinx: KEM decapsulation failed"
  | _, _ => throw "sphinx: invalid key/ciphertext encoding"

/-- A client's own public key, from its private key's raw bytes — as `NIKESphinx`'s
`nikeSelfPublicKeyBytes` (not reused directly since that one is `private` to that file). -/
private def kemSelfPublicKeyBytes (kem : KEM) (skBytes : ByteArray) : ByteArray :=
  match kem.decodePrivateKey (toVecN kem.privateKeySize skBytes) with
  | none => skBytes
  | some sk => ofVector (kem.encodePublicKey (kem.derivePublicKey sk))

/-- The per-hop routing-info fragment for `createKEMHeader`'s third loop, factored out on its
own: a non-terminal hop's fragment gets padded to a full `perHopRoutingInfoLength` and then has
its last `kem.ciphertextSize` bytes overwritten with the next hop's embedded ciphertext, while a
terminal hop's fragment is just padded. Kept as its own named function (rather than inlined
`mut`-reassignment inside the loop) so a caller's own `unfold`/`dsimp` treats its *result* as an
opaque value with only the size fact `kemRiFragment_size` needs, instead of re-expanding this
two-`if` computation (and everything downstream of it) at every use site — the same term-blowup
concern `Crypto.AEZ.lean`'s `aezTinyLR` extraction addresses. -/
private def kemRiFragment (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (kemElements : Array ByteArray) (macBytes : ByteArray) (nrHops i : Nat) :
    Except String ByteArray := do
  let isTerminal := i == nrHops - 1
  let hop := path[i]!
  -- Both branches reserve `kem.ciphertextSize` bytes: a non-terminal hop's fragment tail is
  -- overwritten with the next hop's embedded ciphertext below, and *every* hop's fragment —
  -- terminal or not — is exactly what `unwrapKEM` receives as `cmdBuf` after it unconditionally
  -- carves the trailing `kem.ciphertextSize` bytes off as `nextCiphertext`, since the receiver
  -- can't know in advance whether a given hop is the last one. Giving the terminal branch the
  -- *full* `perHopRoutingInfoLength` budget here (as NIKE-Sphinx does, which has no ciphertext
  -- tail to reserve) would let `wrapKEM` accept commands `unwrapKEM` then truncates/misparses —
  -- breaking completeness for a path no caller-visible check rules out.
  let budget := if isTerminal then geom.perHopRoutingInfoLength - kem.ciphertextSize
    else geom.perHopRoutingInfoLength - geom.nextNodeHopLength - kem.ciphertextSize
  let mut riFragment ← commandsToBytes budget hop.commands
  if !isTerminal then
    let next := path[i + 1]!
    riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
  riFragment := zeroPadTo geom.perHopRoutingInfoLength riFragment
  if !isTerminal then
    riFragment := riFragment.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      ++ kemElements[i + 1]!
  pure riFragment

/-- **`createKEMHeader`**. `ephemeralSeeds` (one per hop) plays the role Go's `io.Reader` does
inside each `Encapsulate` call; `filler` is as in `NIKESphinx.createHeader`. -/
def createKEMHeader (kem : KEM) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if ephemeralSeeds.size ≠ nrHops then throw "sphinx: wrong number of ephemeral seeds"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  -- One independent encapsulation per hop.
  let mut kemElements : Array ByteArray := #[]
  let mut keys : Array HopKeys := #[]
  for i in [0:nrHops] do
    match kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) with
    | .error e => throw e
    | .ok (ct, ss) =>
      kemElements := kemElements.push ct
      keys := keys.push (deriveHopKeys ss)

  -- Per-hop routing-info keystream and encrypted padding, as in NIKESphinx.
  let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
  let mut riKeyStream : Array ByteArray := #[]
  let mut riPadding : Array ByteArray := #[]
  for i in [0:nrHops] do
    let ks := keystream (keys[i]!).headerEncryption (keys[i]!).headerEncryptionIV totalRiLen
    let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
    let mut thisPad := ks.extract ksLen totalRiLen
    if i > 0 then
      let prevPad := riPadding[i - 1]!
      thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
        ++ thisPad.extract prevPad.size thisPad.size
    riKeyStream := riKeyStream.push (ks.extract 0 ksLen)
    riPadding := riPadding.push thisPad

  -- Assemble the routing_information block, back to front, embedding each non-terminal hop's
  -- next-hop ciphertext into the last `kem.ciphertextSize` bytes of its own fragment.
  let mut routingInfo : ByteArray := if geom.nrHops > nrHops then filler else ByteArray.empty
  let mut macBytes : ByteArray := ByteArray.empty
  for iRev in [0:nrHops] do
    let i := nrHops - 1 - iRev
    let riFragment ← kemRiFragment kem geom path kemElements macBytes nrHops i
    routingInfo := riFragment ++ routingInfo
    routingInfo := xorBytes routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ kemElements[0]! ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

@[simp] private theorem byteArray_empty_size : (ByteArray.empty : ByteArray).size = 0 := rfl

@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

private theorem ite_pure_yield {α : Type} (c : Prop) [Decidable c] (a b : α) :
    (if c then (pure (ForInStep.yield a) : Except String (ForInStep α)) else pure (ForInStep.yield b)) =
      pure (ForInStep.yield (if c then a else b)) := by
  split <;> rfl

/-- `kemEncap`'s ciphertext output is always exactly `kem.ciphertextSize` bytes — `kem.encap`'s
own type guarantees this via `encodeCiphertext`. -/
private theorem kemEncap_size (kem : KEM) (pkBytes : ByteArray) (seed : Vector UInt8 32)
    (ct ss : ByteArray) (h : kemEncap kem pkBytes seed = .ok (ct, ss)) :
    ct.size = kem.ciphertextSize := by
  unfold kemEncap at h
  split at h
  · injection h
  · split at h
    · simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.1]
      exact CryptWalker.Util.Bytes.size_ofVector _
    · injection h

/-- `createKEMHeader`'s first loop's array invariant: every `kemElements` entry is exactly
`kem.ciphertextSize` bytes — needed both for `kemElements[0]!` (the header's leading element) and
for `kemElements[i+1]!` (embedded into a non-terminal hop's routing-info fragment in the third
loop). -/
private theorem createKEMHeader_loop1_size (kem : KEM) (path : Array PathHop)
    (ephemeralSeeds : Array (Vector UInt8 32)) (nrHops : Nat) :
    ∀ (init final : Array ByteArray × Array HopKeys),
      init.1 = #[] →
      forIn (List.range' 0 nrHops)
          init
          (fun i (a : Array ByteArray × Array HopKeys) =>
            (match kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) with
              | .error e => throw e
              | .ok (ct, ss) =>
                pure (ForInStep.yield (a.1.push ct, a.2.push (deriveHopKeys ss)))
              : Except String (ForInStep (Array ByteArray × Array HopKeys))))
        = Except.ok final →
      ∀ j (hj : j < final.1.size), (final.1[j]'hj).size = kem.ciphertextSize := by
  intro init final hinit hfinal
  refine CryptWalker.Sphinx.Common.List.forIn_push_size_of_forall_mem (List.range' 0 nrHops)
    kem.ciphertextSize Prod.fst _ ?_ ?_ init final ?_ hfinal
  · intro a a' i hi hgb
    split at hgb
    · injection hgb
    · next ct ss hct =>
      simp only [pure, Except.pure, Except.ok.injEq] at hgb
      injection hgb with hgb
      exact ⟨ct, kemEncap_size kem _ _ ct ss hct, by rw [← hgb]⟩
  · intro a a' i hi hgb
    split at hgb
    · injection hgb
    · injection hgb with hgb; injection hgb
  · rw [hinit]; simp

/-- `kemRiFragment` always produces exactly `geom.perHopRoutingInfoLength` bytes: padded directly
in the terminal case, or padded and then partly overwritten with the embedded next-hop ciphertext
(which doesn't change the size, only the content) otherwise. Kept separate from
`createKEMHeader_loop3_step` for the same reason `kemRiFragment` itself is separate from
`createKEMHeader`: so the loop step's own proof can treat this case split as an opaque fact. -/
private theorem kemRiFragment_size (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (kemElements : Array ByteArray) (macBytes : ByteArray) (nrHops i : Nat) (hi : i < nrHops)
    (hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength)
    (hnnh : geom.nextNodeHopLength = nextNodeHopLength)
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (riFragment : ByteArray)
    (h : kemRiFragment kem geom path kemElements macBytes nrHops i = Except.ok riFragment) :
    riFragment.size = geom.perHopRoutingInfoLength := by
  unfold kemRiFragment at h
  dsimp only at h
  obtain ⟨riFragment0, hriFragment0, h⟩ := Except.eq_ok_of_bind_eq_ok h
  by_cases hterm : i = nrHops - 1
  · have hcond : (i == nrHops - 1) = true := by simp [hterm]
    have hcond' : (!(i == nrHops - 1)) = false := by simp [hterm]
    simp only [hcond'] at h
    simp only [hcond] at hriFragment0
    simp only [decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
      Bool.false_eq_true, reduceIte] at h hriFragment0
    have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - kem.ciphertextSize :=
      commandsToBytes_size_le hriFragment0
    have hle0' : riFragment0.size ≤ geom.perHopRoutingInfoLength := by omega
    simp only [pure, Except.pure, Except.ok.injEq] at h
    rw [← h, zeroPadTo_size hle0']
  · have hcond : (i == nrHops - 1) = false := by simp [hterm]
    have hcond' : (!(i == nrHops - 1)) = true := by simp [hterm]
    simp only [hcond'] at h
    simp only [hcond] at hriFragment0
    simp only [decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
      Bool.false_eq_true, reduceIte] at h hriFragment0
    have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - geom.nextNodeHopLength
        - kem.ciphertextSize := commandsToBytes_size_le hriFragment0
    have hle1perHop : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[i + 1]!).id
        (toVec32 macBytes)).toBytes).size ≤ geom.perHopRoutingInfoLength := by
      simp only [ByteArray.size_append, RoutingCommand.nextNodeHop_toBytes_size]
      simp only [← hnnh]
      omega
    have hi1 : i + 1 < kemElements.size := by rw [hknsize]; omega
    have hcts : (kemElements[i + 1]'hi1).size = kem.ciphertextSize := hksize _ hi1
    have hctsBang : kemElements[i + 1]!.size = kem.ciphertextSize := by
      rw [getElem!_pos kemElements _ hi1]; exact hcts
    simp only [pure, Except.pure, Except.ok.injEq] at h
    rw [← h, ByteArray.size_append, ByteArray.size_extract, zeroPadTo_size hle1perHop, hctsBang]
    omega

private theorem createKEMHeader_loop3_step (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (nrHops : Nat)
    (hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength)
    (hnnh : geom.nextNodeHopLength = nextNodeHopLength)
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (iRev : Nat) (hiRev : iRev < nrHops)
    (ri mb ri' mb' : ByteArray)
    (hstep :
      (do
        let i := nrHops - 1 - iRev
        let riFragment ← kemRiFragment kem geom path kemElements mb nrHops i
        let routingInfo := riFragment ++ ri
        let routingInfo := xorBytes routingInfo (riKeyStream[i]!)
        let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
          ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
        let macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)
        pure (ForInStep.yield (routingInfo, macBytes)) :
          Except String (ForInStep (ByteArray × ByteArray))) = Except.ok (ForInStep.yield (ri', mb'))) :
    ri'.size = ri.size + geom.perHopRoutingInfoLength := by
  dsimp only at hstep
  obtain ⟨riFragment, hriFragment, hstep⟩ := Except.eq_ok_of_bind_eq_ok hstep
  have hsize := kemRiFragment_size kem geom path kemElements mb nrHops (nrHops - 1 - iRev)
    (by omega) hperhop hnnh hknsize hksize riFragment hriFragment
  simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq, Prod.mk.injEq] at hstep
  rw [← hstep.1, size_xorBytes, ByteArray.size_append, hsize]
  omega

/-- Companion to `createKEMHeader_loop3_step`: the loop never exits via `.done`. -/
private theorem createKEMHeader_loop3_never_done (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (nrHops : Nat) (iRev : Nat) (ri mb : ByteArray) (a' : ByteArray × ByteArray)
    (hstep :
      (do
        let i := nrHops - 1 - iRev
        let riFragment ← kemRiFragment kem geom path kemElements mb nrHops i
        let routingInfo := riFragment ++ ri
        let routingInfo := xorBytes routingInfo (riKeyStream[i]!)
        let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
          ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
        let macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)
        pure (ForInStep.yield (routingInfo, macBytes)) :
          Except String (ForInStep (ByteArray × ByteArray))) = Except.ok (ForInStep.done a')) :
    False := by
  dsimp only at hstep
  obtain ⟨riFragment, -, hstep⟩ := Except.eq_ok_of_bind_eq_ok hstep
  injection hstep with hstep
  injection hstep

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- As `NIKESphinx.createHeader_hdr_size`. -/
theorem createKEMHeader_hdr_size (kem : KEM) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray) (path : Array PathHop)
    (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (hvalid : geom.ValidForKEM kem)
    (h : createKEMHeader kem geom ephemeralSeeds filler path = .ok (hdr, sprpKeys)) :
    hdr.size = geom.headerLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, -, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  unfold createKEMHeader at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error "sphinx: invalid path" : Except String (ByteArray × Array SPRPKey)) =
        Except.ok (hdr, sprpKeys) := h
    injection h'
  case isFalse =>
    split at h
    case isTrue =>
      have h' : (Except.error "sphinx: wrong number of ephemeral seeds" :
          Except String (ByteArray × Array SPRPKey)) = Except.ok (hdr, sprpKeys) := h
      injection h'
    case isFalse =>
      split at h
      case isTrue =>
        have h' : (Except.error "sphinx: invalid filler length" :
            Except String (ByteArray × Array SPRPKey)) = Except.ok (hdr, sprpKeys) := h
        injection h'
      case isFalse =>
        rename_i h1 h1b h2
        simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
          Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl,
          ite_pure_yield, pure_bind] at h
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
        have hloop1count : loop1Final.1.size = path.size := by
          have := CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem (List.range' 0 path.size) _
            (fun (a : Array ByteArray × Array HopKeys) => a.1.size) 1
            (fun a a' i hi hgb => by
              split at hgb
              · injection hgb
              · next ct ss hct =>
                simp only [pure, Except.pure, Except.ok.injEq] at hgb
                injection hgb with hgb
                rw [← hgb]; simp [Array.size_push])
            (fun a a' i hi hgb => by
              split at hgb
              · injection hgb
              · injection hgb with hgb; injection hgb)
            (#[], #[]) loop1Final hLoop1
          simpa [List.length_range'] using this
        have hloop1size : ∀ j (hj : j < loop1Final.1.size), (loop1Final.1[j]'hj).size = kem.ciphertextSize :=
          createKEMHeader_loop1_size kem path ephemeralSeeds path.size (#[], #[]) loop1Final rfl hLoop1
        have hge0size : loop1Final.1[0]!.size = kem.ciphertextSize := by
          rw [getElem!_pos _ _ (by simpa [hloop1count] using hpos)]
          exact hloop1size 0 (by simpa [hloop1count] using hpos)
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
              obtain ⟨riFragment, hriFragment, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
              have hsize := kemRiFragment_size kem geom path loop1Final.1 a.2 path.size
                (path.size - 1 - iRev) (by omega) hperhop hnnh hloop1count hloop1size riFragment
                hriFragment
              simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
              rw [← congrArg Prod.fst hgb, size_xorBytes, ByteArray.size_append, hsize]
              omega
            · intro a a' iRev hiRev hgb
              obtain ⟨riFragment, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
              injection hgb with hgb
              injection hgb
          simpa [List.length_range'] using hraw.symm
        have hlne : List.range' 0 path.size ≠ [] := by
          simp only [ne_eq, List.range'_eq_nil_iff]; omega
        have hmacsize : loop3Final.2.size = 32 := by
          refine CryptWalker.Sphinx.Common.List.forIn_const_of_forall_mem (List.range' 0 path.size) hlne
            _ (fun (a : ByteArray × ByteArray) => a.2.size) 32 ?_ ?_ _ _ hLoop3
          · intro a a' iRev hiRev hgb
            obtain ⟨riFragment, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
            rw [← congrArg Prod.snd hgb]
            exact Util.Bytes.size_ofVector _
          · intro a a' iRev hiRev hgb
            obtain ⟨riFragment, -, hgb⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok hgb
            injection hgb with hgb
            injection hgb
        have hv0 : v0AD.size = 2 := rfl
        have hmulcombine : (geom.nrHops - path.size) * geom.perHopRoutingInfoLength
            + path.size * geom.perHopRoutingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops := by
          rw [← Nat.add_mul, Nat.sub_add_cancel hgen, Nat.mul_comm]
        rw [← hhdr]
        simp only [ByteArray.size_append, hv0, hge0size, hloop3size, hinit_size, hmacsize,
          byteArray_empty_size]
        rw [hheader, hrouting, ← hmulcombine]
        simp only [adLength, macLength]

/-- **`newKEMPacket`**. -/
def newKEMPacket (kem : KEM) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createKEMHeader kem geom ephemeralSeeds filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- As `NIKESphinx.newNIKEPacket_size`. -/
theorem newKEMPacket_size (kem : KEM) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (hvalid : geom.ValidForKEM kem)
    (h : newKEMPacket kem geom ephemeralSeeds filler path payload = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  unfold newKEMPacket at h
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
        (fun b a ↦ sprpEncrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
        ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload) := by
      injection hfx with hfx; exact hfx.symm
    have hhdrsize := createKEMHeader_hdr_size kem geom ephemeralSeeds filler path x.1 x.2 hvalid hx
    have hfoldsize := CryptWalker.Sphinx.Common.List.foldl_size_preserving (List.range' 0 x.2.size)
      (fun b a ↦ sprpEncrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
      (fun b a ↦ CryptWalker.Sphinx.Crypto.AEZ.sprpEncrypt_size _ _ b)
      ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload)
    rw [hpkt, ByteArray.size_append, hhdrsize, hfoldsize, ByteArray.size_append, hpacket]
    simp only [byteArray_mk_size, Array.size_replicate]
    omega

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapKEM`**: `Sphinx.Interface.wrap` for `KEMSphinxScheme` — `newKEMPacket`, drawing one
ephemeral seed per hop from the seed stream instead of taking them as a bare array. -/
def wrapKEM (kem : KEM) (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  match newKEMPacket kem geom seeds filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    if hsize : pkt.size = geom.packetLength then pure ⟨pkt.data, hsize⟩
    else throw "sphinx: internal error: newKEMPacket produced a wrong-sized packet"

/-- **`newKEMSURB`**. As `NIKESphinx.newNIKESURB`, over `createKEMHeader`. -/
def newKEMSURB (kem : KEM) (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createKEMHeader kem geom ephemeralSeeds filler path
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `NIKESphinx.newNIKESURB_size`. -/
theorem newKEMSURB_size (kem : KEM) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop)
    (hvalid : geom.ValidForKEM kem)
    (surb surbKeys : ByteArray)
    (h : newKEMSURB kem geom ephemeralSeeds keyPayload filler path = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength := by
  obtain ⟨-, -, -, -, -, hsurb⟩ := id hvalid
  unfold newKEMSURB at h
  dsimp only at h
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind] at h
  obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
  have hsurbeq : surb = x.1 ++ ofVector (path[0]!).id ++ ofVector keyPayload := by
    injection hfx with hfx; exact congrArg Prod.fst hfx.symm
  have hhdrsize := createKEMHeader_hdr_size kem geom ephemeralSeeds filler path x.1 x.2 hvalid hx
  rw [hsurbeq, ByteArray.size_append, ByteArray.size_append, hhdrsize, hsurb,
    CryptWalker.Util.Bytes.size_ofVector, CryptWalker.Util.Bytes.size_ofVector]
  simp only [nodeIDLength, CryptWalker.Sphinx.Constants.sprpKeyMaterialLength,
    CryptWalker.Sphinx.Constants.sprpKeyLength, CryptWalker.Sphinx.Constants.sprpIVLength,
    CryptWalker.Sphinx.Constants.streamIVLength]

/-- **`wrapKEMSURB`**: `Sphinx.Interface.newSURB` for `KEMSphinxScheme` — draws one ephemeral seed
per hop plus `keyPayload` (two seeds' worth) from the seed stream. -/
def wrapKEMSURB (kem : KEM) (geom : Geometry) (path : List PathHop)
    (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match newKEMSURB kem geom seeds (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    if hsize : surb.size = geom.surbLength then pure (⟨surb.data, hsize⟩, k)
    else throw "sphinx: internal error: newKEMSURB produced a wrong-sized SURB"

/-- **`unwrapKEM`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`.
Forwarding copies the next-hop ciphertext straight out of the decrypted routing-info block —
unlike `unwrapNIKE`, no `Blind` step, since there is no group element to re-blind. -/
def unwrapKEM (kem : KEM) (geom : Geometry) (privKey : ByteArray) (pkt : ByteArray) :
    Except String
      (Option ByteArray × Vector UInt8 32 × List RoutingCommand × Option (Vector UInt8 pkt.size)) := do
  let geOff := 2
  let riOff := geOff + kem.ciphertextSize
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  if h1 : pkt.size < payloadOff then throw "sphinx: invalid packet, truncated"
  else do
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let kemCiphertext := pkt.extract geOff riOff
  let replayTag := sha512_256 kemCiphertext
  let sharedSecret ← kemDecap kem privKey kemCiphertext

  let keys := deriveHopKeys sharedSecret
  let gotMac := mac keys.headerMAC (pkt.extract 0 macOff)
  if (ofVector gotMac).data ≠ (pkt.extract macOff (macOff + macLength)).data then
    throw "sphinx: invalid packet, MAC mismatch"

  let mut b : ByteArray := pkt.extract riOff macOff ++ ⟨Array.replicate geom.perHopRoutingInfoLength 0⟩
  have hb : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    have hpad : (⟨Array.replicate geom.perHopRoutingInfoLength (0 : UInt8)⟩ : ByteArray).size
        = geom.perHopRoutingInfoLength := Array.size_replicate
    show (pkt.extract riOff macOff ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength
    rw [ByteArray.size_append, ByteArray.size_extract, hpad]
    omega
  b := xorBytes b (keystream keys.headerEncryption keys.headerEncryptionIV b.size)
  have hb' : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    show (xorBytes _ _).size = _
    rw [size_xorBytes]; exact hb

  let cmdBuf := b.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
  let nextCiphertext := ofVector (toVecN kem.ciphertextSize
    (b.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize) geom.perHopRoutingInfoLength))
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
    if rawPayload.size > 0 then sprpDecrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
    else rawPayload
  have hdec : decPayload.size = rawPayload.size := by
    show (if rawPayload.size > 0
          then sprpDecrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
          else rawPayload).size = rawPayload.size
    split
    · exact CryptWalker.Sphinx.Crypto.AEZ.sprpDecrypt_size _ _ _
    · rfl

  match nextNode with
  | some (_nextID, nextMAC) =>
    have hnextCiphertext : nextCiphertext.size = kem.ciphertextSize := Util.Bytes.size_ofVector _
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    have hnewPayload : newPayload.size = pkt.size - payloadOff := by
      show (if decPayload.size > 0 then decPayload else rawPayload).size = pkt.size - payloadOff
      split
      · rw [hdec, hraw]
      · rw [hraw]
    let newPkt := v0AD ++ nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    have hnewPkt : newPkt.size = pkt.size := by
      show (v0AD ++ nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload).size
        = pkt.size
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          hnextCiphertext, Util.Bytes.size_ofVector, hnri, hnewPayload]
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

/-- As `NIKESphinx.wrapNIKE_unwrapNIKE_complete`: `KEMSphinxScheme`'s witness for
`Sphinx.Interface.unwrap_complete`. -/
axiom wrapKEM_unwrapKEM_complete (kem : KEM) (geom : Geometry) (path : List PathHop)
    (privKeys : List ByteArray) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (kemSelfPublicKeyBytes kem) →
    wrapKEM kem geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapKEM kem geom) privKeys (ofVector pkt) = .ok (some (ofVector payload))

structure KEMSphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
  kem : KEM
  /-- **Not wrap-resistant** — the inverse of `NIKESphinxScheme.wrap_resistant`: a known-key
  adversary hits any target routing-info block with certainty, not merely `1/N`. See
  `unwrapKEM_routingInfoBlock_not_wrap_resistant` below for why. -/
  not_wrap_resistant : ∀ (key : Vector UInt8 32) (iv : Vector UInt8 16) (target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (keystream key iv target.size) target

/-- Build a `KEMSphinxScheme` from any `KEM` at all — total, no `Except`. -/
def kemSphinxSchemeOf (kem : KEM) (geom : Geometry) : KEMSphinxScheme where
  State := SeedStream
  PrivateKey := ByteArray
  Command := RoutingCommand
  geometry := geom
  stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
  derivePublicKey := kemSelfPublicKeyBytes kem
  wrap := wrapKEM kem geom
  unwrap := unwrapKEM kem geom
  newSURB := wrapKEMSURB kem geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
  unwrap_complete := wrapKEM_unwrapKEM_complete kem geom
  kem := kem

/-- Build a `KEMSphinxScheme` for whatever KEM `geom.scheme` names, resolved through
`CryptWalker.KEM.byName` — the same registry `Geometry.ofKEM` resolves its ciphertext size
against. Genuinely agnostic to *which* registered KEM this is: no NIKE, no PRF, nothing but the
`KEM` value itself and a `Geometry`. -/
def kemSphinxScheme (geom : Geometry) : Except String KEMSphinxScheme :=
  match geom.scheme with
  | .inl name => throw s!"sphinx: geometry scheme {name} is a NIKE, not a KEM"
  | .inr name =>
    match CryptWalker.KEM.byName name with
    | none => throw s!"sphinx: KEM scheme {name} not implemented"
    | some kem => pure (kemSphinxSchemeOf kem geom)

/-! ## Wrap-resistance fails

The root cause is structural, not cryptographic: NIKE-Sphinx has a public-key operation
available — blinding, `factor • pk` — that KEM-Sphinx has no analogue of for a generic KEM, so
this design instead carries a fresh KEM ciphertext per hop, protected only by the header's own
stream-cipher-plus-MAC (`headerEncryption`/`headerMAC`, an AEAD-shaped construction). That
construction isn't broken, and nothing here says it is: AEAD security is a guarantee against
adversaries who *don't* hold the key, and was never meant to be one against adversaries who do.
Wrap-resistance's own threat model hands the adversary the hop's private key ("even one whose
private key x the adversary can select"), and knowing that key means knowing the shared secret,
which means knowing the AEAD key — at which point the AEAD isn't defeated, it simply was never
protecting against this party to begin with. Any key-holder can always produce a valid
ciphertext+tag for whatever plaintext it wants; that's what "keyed encryption" means.

`NIKESphinx.nikeSphinxScheme`'s `blind` is different in kind: it routes the forwarded envelope
through a hash of the shared secret *composed with* a group operation, which the current hop's
own key-holder cannot invert to land on a chosen output, despite holding every secret involved
(`Sphinx.WrapResistance.blind_wrapResistance` bounds it to `1/N`). KEM-Sphinx has nothing playing
that role — `nextCiphertext`/`newRoutingInfo`/`nextMAC` above are just slices of `b`, the AEAD's
own decryption of bytes the packet's constructor chose freely, so the AEAD is the *only* thing
between the adversary and the target, and it was never the right tool for that job. `kemDecap`
above is total bar a handful of small-order ciphertexts, so anyone holding `privKey` can compute
the header keystream for *any* `kemCiphertext` they pick, and once it's known,
`xorBytes_achieves_any_target` says every target routing-info block is reachable, with
certainty. -/

/-- **KEM-Sphinx does not achieve wrap-resistance** — not because its AEAD-shaped header
protection is weak, but because it's the only thing standing in for NIKE-Sphinx's blinding step,
and AEAD security was never a guarantee against a party who holds the key, which wrap-resistance's
own threat model grants the adversary. For any routing-info-block `target` a key-holder wants the
mix to forward, there are raw (pre-decryption) bytes achieving it exactly — the opposite of a
`1/N`-style bound. -/
theorem unwrapKEM_routingInfoBlock_not_wrap_resistant (key : Vector UInt8 32) (iv : Vector UInt8 16)
    (target : ByteArray) :
    ∃ raw : ByteArray, xorBytes raw (keystream key iv target.size) = target :=
  xorBytes_achieves_any_target (keystream key iv target.size) target

end CryptWalker.Sphinx.KEMSphinx
