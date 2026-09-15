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
import CryptWalker.Sphinx.Crypto.WideBlockCipher
import CryptWalker.Sphinx.Crypto.MAC
import CryptWalker.Sphinx.Crypto.GenericKDF
import CryptWalker.Sphinx.Crypto.StreamCipher
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
open CryptWalker.Sphinx.NIKESphinx (HopKeys)
open CryptWalker.Sphinx.Crypto.WideBlockCipher (WideBlockCipher)
open CryptWalker.Sphinx.Crypto.MAC (MAC)
open CryptWalker.Sphinx.Crypto.GenericKDF (KDF)
open CryptWalker.Sphinx.Crypto.StreamCipher (StreamCipher)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)

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

/-- As `NIKESphinx.deriveHopKeys`, generic over which `KDF` does the expansion —
`GenericKDF.packetKeysFrom` reproduces `sphinxKDF`'s own domain string and slicing exactly (see
its doc comment), so this agrees with `NIKESphinx.deriveHopKeys sharedSecret` definitionally when
`kdfS = GenericKDF.hkdfSha256Expand`. `blindingFactor` is the one `HopKeys` field this never
populates (`ByteArray.empty`, matching `HopKeys`' own doc comment: unused on the KEM side, since
there is no blinding chain to feed it into). -/
private def deriveHopKeysG (kdfS : KDF) (sharedSecret : ByteArray) : HopKeys :=
  let pk := CryptWalker.Sphinx.Crypto.GenericKDF.packetKeysFrom kdfS sharedSecret
  { headerMAC := pk.headerMAC
    headerEncryption := pk.headerEncryption
    headerEncryptionIV := pk.headerEncryptionIV
    payloadEncryption := pk.payloadEncryption
    blindingFactor := ByteArray.empty }

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
inside each `Encapsulate` call; `filler` is as in `NIKESphinx.createHeader`. Generic in the MAC,
KDF and stream cipher (`macS`/`kdfS`/`streamS`) — never calls `HMAC`/`KDF`/`Stream` by name. -/
def createKEMHeader (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
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
      keys := keys.push (deriveHopKeysG kdfS ss)

  -- Per-hop routing-info keystream and encrypted padding, as in NIKESphinx.
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
    macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)

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

/-- **The honest-pairing KEM round trip, at the byte level.** If `pkBytes` is `skBytes`'s own
public key (`kemSelfPublicKeyBytes`) and encapsulating against it succeeds, decapsulating with
`skBytes` recovers the same shared secret. Reduces entirely to `KEM.honestRoundTrip` (the
`generate`-independent round-trip law added for exactly this purpose) plus the encode/decode round
trips already on `KEM` — no AEZ/HMAC/KDF/stream-cipher content, and no assumption about which `KEM`
this is beyond its own laws. -/
theorem kemEncap_kemDecap_of_honest (kem : KEM) (skBytes : ByteArray) (seedV : Vector UInt8 32)
    (ctBytes ssBytes : ByteArray)
    (henc : kemEncap kem (kemSelfPublicKeyBytes kem skBytes) seedV = .ok (ctBytes, ssBytes)) :
    kemDecap kem skBytes ctBytes = .ok ssBytes := by
  obtain ⟨sk, hsk⟩ := kem.decodePrivateKey_total (toVecN kem.privateKeySize skBytes)
  unfold kemSelfPublicKeyBytes at henc
  rw [hsk] at henc
  unfold kemEncap at henc
  rw [toVecN_ofVector, kem.decode_encode_pub] at henc
  dsimp only at henc
  generalize hgb : kem.encap (kem.derivePublicKey sk) (kem.stateFromSeed seedV) = r at henc
  cases r with
  | error e s' => simp only [pure, Except.pure] at henc; injection henc
  | ok val s' =>
    obtain ⟨ct, ss⟩ := val
    simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at henc
    obtain ⟨hct, hss⟩ := henc
    obtain ⟨t', hd⟩ := kem.honestRoundTrip sk (kem.stateFromSeed seedV) ct ss s' hgb
      (kem.stateFromSeed (Vector.replicate 32 0))
    unfold kemDecap
    rw [hsk, ← hct, toVecN_ofVector, kem.decode_encode_ct]
    dsimp only
    rw [hd]
    dsimp only
    rw [← hss]
    rfl

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
private theorem createKEMHeader_loop1_size (kem : KEM) (kdfS : KDF) (path : Array PathHop)
    (ephemeralSeeds : Array (Vector UInt8 32)) (nrHops : Nat) :
    ∀ (init final : Array ByteArray × Array HopKeys),
      init.1 = #[] →
      forIn (List.range' 0 nrHops)
          init
          (fun i (a : Array ByteArray × Array HopKeys) =>
            (match kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) with
              | .error e => throw e
              | .ok (ct, ss) =>
                pure (ForInStep.yield (a.1.push ct, a.2.push (deriveHopKeysG kdfS ss)))
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

private theorem zeroPadTo_eq_append (b : ByteArray) (n : Nat) (h : b.size ≤ n) :
    zeroPadTo n b = b ++ ⟨Array.replicate (n - b.size) 0⟩ := by
  unfold zeroPadTo
  split
  · next hge =>
    have hz : n - b.size = 0 := by omega
    rw [hz]
    show b = b ++ ByteArray.empty
    rw [ByteArray.append_empty]
  · rfl

/-- **`kemRiFragment`'s content, terminal-hop case**: the leading `perHop - ctSize` bytes parse
back to exactly the hop's own commands, and the trailing `ctSize` bytes are all zero (the fixed
tail every terminal fragment reserves, per `kemRiFragment`'s own doc comment — matching what
`unwrapKEM` unconditionally carves off as `nextCiphertext`, whether or not the hop turns out to be
terminal). -/
theorem kemRiFragment_content_terminal (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (kemElements : Array ByteArray) (macBytes : ByteArray) (nrHops i : Nat) (hi : i < nrHops)
    (hterm : i = nrHops - 1)
    (hcle : kem.ciphertextSize ≤ geom.perHopRoutingInfoLength)
    (hcmdnn : ∀ c ∈ (path[i]!).commands, c ≠ .null)
    (riFragment : ByteArray)
    (h : kemRiFragment kem geom path kemElements macBytes nrHops i = Except.ok riFragment) :
    parseAll (riFragment.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize))
        = .ok (path[i]!).commands ∧
      riFragment.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
          geom.perHopRoutingInfoLength
        = (⟨Array.replicate kem.ciphertextSize 0⟩ : ByteArray) := by
  unfold kemRiFragment at h
  dsimp only at h
  obtain ⟨riFragment0, hriFragment0, h⟩ := Except.eq_ok_of_bind_eq_ok h
  have hcond : (i == nrHops - 1) = true := by simp [hterm]
  have hcond' : (!(i == nrHops - 1)) = false := by simp [hterm]
  simp only [hcond'] at h
  simp only [hcond] at hriFragment0
  simp only [decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
    Bool.false_eq_true, reduceIte] at h hriFragment0
  simp only [pure, Except.pure, Except.ok.injEq] at h
  have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - kem.ciphertextSize :=
    commandsToBytes_size_le hriFragment0
  have hle0' : riFragment0.size ≤ geom.perHopRoutingInfoLength := by omega
  rw [← h, zeroPadTo_eq_append riFragment0 geom.perHopRoutingInfoLength hle0']
  constructor
  · rw [extract_append_le riFragment0 _ hle0, replicate_extract _ _ _ (by omega : _ ≤
      geom.perHopRoutingInfoLength - riFragment0.size), Nat.sub_zero,
      ← zeroPadTo_eq_append riFragment0 (geom.perHopRoutingInfoLength - kem.ciphertextSize) hle0]
    exact parseAll_commandsToBytes (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      (geom.perHopRoutingInfoLength - kem.ciphertextSize) (path[i]!).commands hcmdnn riFragment0
      hriFragment0 hle0
  · rw [extract_append_of_ge riFragment0 _ hle0]
    have heq : (geom.perHopRoutingInfoLength - riFragment0.size)
        - (geom.perHopRoutingInfoLength - kem.ciphertextSize - riFragment0.size)
        = kem.ciphertextSize := by omega
    rw [replicate_extract _ _ _ (le_refl (geom.perHopRoutingInfoLength - riFragment0.size)), heq]

/-- **`kemRiFragment`'s content, non-terminal-hop case**: the leading `perHop - ctSize` bytes
parse back to the hop's own commands followed by the embedded `NextNodeHop` command (carrying the
*previous* iteration's MAC — `macBytes`, as passed into `kemRiFragment` — and the next hop's ID),
and the trailing `ctSize` bytes are the next hop's own embedded KEM ciphertext. -/
theorem kemRiFragment_content_nonterminal (kem : KEM) (geom : Geometry) (path : Array PathHop)
    (kemElements : Array ByteArray) (macBytes : ByteArray) (nrHops i : Nat) (hi : i < nrHops)
    (hterm : i ≠ nrHops - 1)
    (hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength)
    (hnnh : geom.nextNodeHopLength = nextNodeHopLength)
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hcmdnn : ∀ c ∈ (path[i]!).commands, c ≠ .null)
    (riFragment : ByteArray)
    (h : kemRiFragment kem geom path kemElements macBytes nrHops i = Except.ok riFragment) :
    parseAll (riFragment.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize))
        = .ok ((path[i]!).commands
          ++ [RoutingCommand.nextNodeHop (path[i + 1]!).id (toVec32 macBytes)]) ∧
      riFragment.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
          geom.perHopRoutingInfoLength
        = kemElements[i + 1]! := by
  unfold kemRiFragment at h
  dsimp only at h
  obtain ⟨riFragment0, hriFragment0, h⟩ := Except.eq_ok_of_bind_eq_ok h
  have hcond : (i == nrHops - 1) = false := by simp [hterm]
  have hcond' : (!(i == nrHops - 1)) = true := by simp [hterm]
  simp only [hcond'] at h
  simp only [hcond] at hriFragment0
  simp only [decide_eq_true_eq, eq_self_iff_true, if_true, if_false, ite_true, ite_false,
    Bool.false_eq_true, reduceIte] at h hriFragment0
  simp only [pure, Except.pure, Except.ok.injEq] at h
  have hle0 : riFragment0.size ≤ geom.perHopRoutingInfoLength - geom.nextNodeHopLength
      - kem.ciphertextSize := commandsToBytes_size_le hriFragment0
  have hi1 : i + 1 < kemElements.size := by rw [hknsize]; omega
  have hctsBang : kemElements[i + 1]!.size = kem.ciphertextSize := by
    rw [getElem!_pos kemElements _ hi1]; exact hksize _ hi1
  have hnn : (RoutingCommand.nextNodeHop (path[i + 1]!).id (toVec32 macBytes)).toBytes.size
      = geom.nextNodeHopLength := by rw [RoutingCommand.nextNodeHop_toBytes_size, hnnh]
  have hcb : commandsToBytes (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      ((path[i]!).commands ++ [RoutingCommand.nextNodeHop (path[i + 1]!).id (toVec32 macBytes)])
      = .ok (riFragment0 ++ (RoutingCommand.nextNodeHop (path[i + 1]!).id (toVec32 macBytes)).toBytes) :=
    commandsToBytes_append_singleton hriFragment0 _ (by rw [hnn]; omega)
  have hle1 : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[i + 1]!).id
      (toVec32 macBytes)).toBytes).size ≤ geom.perHopRoutingInfoLength - kem.ciphertextSize := by
    rw [ByteArray.size_append, hnn]; omega
  have hle1' : (riFragment0 ++ (RoutingCommand.nextNodeHop (path[i + 1]!).id
      (toVec32 macBytes)).toBytes).size ≤ geom.perHopRoutingInfoLength := by omega
  -- `riFragment` (nonterminal branch) = `zeroPadTo (P-C) (riFragment0 ++ nnBytes) ++ kemElements[i+1]!`.
  rw [← h, zeroPadTo_eq_append _ geom.perHopRoutingInfoLength hle1',
    extract_append_le _ _ hle1, replicate_extract _ _ _ (by omega), Nat.sub_zero,
    ← zeroPadTo_eq_append _ (geom.perHopRoutingInfoLength - kem.ciphertextSize) hle1]
  have hzp : (zeroPadTo (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      (riFragment0 ++ (RoutingCommand.nextNodeHop (path[i + 1]!).id (toVec32 macBytes)).toBytes)).size
      = geom.perHopRoutingInfoLength - kem.ciphertextSize := zeroPadTo_size hle1
  constructor
  · rw [extract_append_le _ _ (le_of_eq hzp), hzp, Nat.sub_self, ByteArray.extract_same,
      ByteArray.append_empty]
    exact parseAll_commandsToBytes _ _ _ (by
      intro c hc
      simp only [List.mem_append, List.mem_singleton] at hc
      rcases hc with hc | hc
      · exact hcmdnn c hc
      · rw [hc]; intro hcon; injection hcon) _ hcb hle1
  · rw [extract_append_of_ge _ _ (le_of_eq hzp), hzp]
    have hsub : geom.perHopRoutingInfoLength
        - (geom.perHopRoutingInfoLength - kem.ciphertextSize) = kem.ciphertextSize := by omega
    rw [hsub, Nat.sub_self]
    conv_rhs => rw [← ByteArray.extract_zero_size (b := kemElements[i+1]!)]
    rw [hctsBang]

/-- The per-hop keystream/padding loop's one-step accumulator update: `ks`'s leading `ksLen` bytes
feed `riKeyStream`, and `ks`'s trailing `(i+1)*perHop` bytes, cascaded against the previous hop's
own padding (`prevPad`) when there is one, feed `riPadding`. This is the loop's whole body — it
never `throw`s or binds `←`, so `List.forIn_pure_yield_eq_foldl` collapses its `forIn` to a bare
`List.foldl` over this function, losing the `Except`-monadic structure `createKEMHeader_loop3_trace`
needed `forIn_exists_trace` for. -/
private def loop2Step (streamS : StreamCipher) (geom : Geometry) (keys : Array HopKeys)
    (st : Array ByteArray × Array ByteArray) (i : Nat) : Array ByteArray × Array ByteArray :=
  let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
  let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
    (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
  let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
  let thisPad0 := ks.extract ksLen totalRiLen
  let thisPad := if i > 0 then
      let prevPad := st.2[i - 1]!
      xorBytes (thisPad0.extract 0 prevPad.size) prevPad ++ thisPad0.extract prevPad.size thisPad0.size
    else thisPad0
  (st.1.push (ks.extract 0 ksLen), st.2.push thisPad)

/-- **The full trace of `createKEMHeader`'s second loop** (as `createKEMHeader_loop3_trace` for the
third): the actual sequence of `(riKeyStream, riPadding)` array pairs, one per hop, built from the
generic `List.foldl_exists_trace` rather than a bespoke induction. -/
private theorem createKEMHeader_loop2_trace (streamS : StreamCipher) (geom : Geometry)
    (keys : Array HopKeys) (nrHops : Nat) :
    ∃ s : Nat → Array ByteArray × Array ByteArray, s 0 = (#[], #[]) ∧
      s nrHops = (List.range' 0 nrHops).foldl (loop2Step streamS geom keys) (#[], #[]) ∧
      ∀ j (hj : j < nrHops), s (j + 1) = loop2Step streamS geom keys (s j) j := by
  obtain ⟨s, hs0, hsl, hstep⟩ :=
    CryptWalker.Sphinx.Common.List.foldl_exists_trace (List.range' 0 nrHops)
      (loop2Step streamS geom keys) (#[], #[])
  refine ⟨s, hs0, by simpa using hsl, ?_⟩
  intro j hj
  have hj' : j < (List.range' 0 nrHops).length := by simpa using hj
  have := hstep j hj'
  simpa using this

/-- The trace's array sizes track the step index exactly, by a trivial induction on the pushes
`loop2Step` performs every iteration. -/
private theorem loop2_trace_size (streamS : StreamCipher) (geom : Geometry) (keys : Array HopKeys)
    (nrHops : Nat) (s : Nat → Array ByteArray × Array ByteArray) (hs0 : s 0 = (#[], #[]))
    (hstep : ∀ j (hj : j < nrHops), s (j + 1) = loop2Step streamS geom keys (s j) j) :
    ∀ j (hj : j ≤ nrHops), (s j).1.size = j ∧ (s j).2.size = j := by
  intro j hj
  induction j with
  | zero => simp [hs0]
  | succ j ih =>
    have hj' : j < nrHops := by omega
    obtain ⟨ih1, ih2⟩ := ih (by omega)
    rw [hstep j hj']
    unfold loop2Step
    dsimp only
    simp only [Array.size_push, ih1, ih2]
    trivial

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

/-- **`createKEMHeader`'s first loop, at the content level**: `kemElements[i]!` and `keys[i]!` are
exactly the ciphertext and derived hop keys `kemEncap` produced at hop `i` — the fact
`kemEncap_kemDecap_of_honest` needs paired against `kemDecap` at `unwrapKEM`'s matching hop. -/
private theorem createKEMHeader_loop1_content (kem : KEM) (kdfS : KDF) (path : Array PathHop)
    (ephemeralSeeds : Array (Vector UInt8 32)) (nrHops : Nat)
    (final : Array ByteArray × Array HopKeys)
    (hfinal : forIn (List.range' 0 nrHops) (#[], #[])
        (fun i (a : Array ByteArray × Array HopKeys) =>
          (match kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) with
            | .error e => throw e
            | .ok (ct, ss) =>
              pure (ForInStep.yield (a.1.push ct, a.2.push (deriveHopKeysG kdfS ss)))
            : Except String (ForInStep (Array ByteArray × Array HopKeys)))) = Except.ok final)
    (i : Nat) (hi : i < nrHops) :
    ∃ ct ss, kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) = Except.ok (ct, ss) ∧
      final.1[i]! = ct ∧ final.2[i]! = deriveHopKeysG kdfS ss := by
  have hnd : ∀ (b : Nat) (a a' : Array ByteArray × Array HopKeys), b ∈ List.range' 0 nrHops →
      (fun i (a : Array ByteArray × Array HopKeys) =>
        (match kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) with
          | .error e => throw e
          | .ok (ct, ss) =>
            pure (ForInStep.yield (a.1.push ct, a.2.push (deriveHopKeysG kdfS ss)))
          : Except String (ForInStep (Array ByteArray × Array HopKeys)))) b a
        ≠ Except.ok (ForInStep.done a') := by
    intro b a a' _hb hcontra
    dsimp only at hcontra
    split at hcontra <;> simp_all [pure, Except.pure]
  obtain ⟨s, hs0, hsl, hstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
    (List.range' 0 nrHops) _ hnd (#[], #[]) final hfinal
  have hlen : (List.range' 0 nrHops).length = nrHops := by simp
  have hsl' : s nrHops = final := by rw [← hlen]; exact hsl
  have hstep' : ∀ j, j < nrHops →
      (match kemEncap kem (path[j]!).publicKey (ephemeralSeeds[j]!) with
        | .error e => throw e
        | .ok (ct, ss) =>
          pure (ForInStep.yield ((s j).1.push ct, (s j).2.push (deriveHopKeysG kdfS ss)))
        : Except String (ForInStep (Array ByteArray × Array HopKeys)))
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
      split at hstepj
      · simp only [reduceCtorEq] at hstepj
      · next ct ss hct =>
        simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
        rw [← hstepj]
        simp [ih1, ih2]
  have hstable1 := Array.getElem!_stable_of_pushes (fun j => (s j).1) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      split at hstepj
      · simp only [reduceCtorEq] at hstepj
      · next ct ss hct =>
        simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
        exact ⟨ct, (congrArg Prod.fst hstepj).symm⟩)
    (fun j hj => (hsize j hj).1)
  have hstable2 := Array.getElem!_stable_of_pushes (fun j => (s j).2) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      split at hstepj
      · simp only [reduceCtorEq] at hstepj
      · next ct ss hct =>
        simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
        exact ⟨deriveHopKeysG kdfS ss, (congrArg Prod.snd hstepj).symm⟩)
    (fun j hj => (hsize j hj).2)
  have h1 : final.1[i]! = (s (i + 1)).1[i]! := by
    rw [← hsl']; exact hstable1 i nrHops hi (le_refl _)
  have h2 : final.2[i]! = (s (i + 1)).2[i]! := by
    rw [← hsl']; exact hstable2 i nrHops hi (le_refl _)
  have hstepi := hstep' i hi
  have hpi1 : (s i).1.size = i := (hsize i (by omega)).1
  have hpi2 : (s i).2.size = i := (hsize i (by omega)).2
  split at hstepi
  · simp only [reduceCtorEq] at hstepi
  · next ct ss hct =>
    simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepi
    refine ⟨ct, ss, hct, ?_, ?_⟩
    · rw [h1, ← congrArg Prod.fst hstepi, getElem!_push_eq' _ _ _ hpi1.symm]
    · rw [h2, ← congrArg Prod.snd hstepi, getElem!_push_eq' _ _ _ hpi2.symm]

/-- **`createKEMHeader`'s second loop, at the content level — kept in its native `forIn`/`Except`
shape.** As `loop2_content`, but proved directly against the loop's own `forIn` (via
`List.forIn_exists_trace`) instead of the `List.foldl` form `List.forIn_pure_yield_eq_foldl` would
collapse it to. The two are propositionally the same loop, but the *assembled* completeness proof
never applies that collapsing simp lemma to begin with (only `createKEMHeader_hdr_size` does) — so
the hypothesis it actually gets from unfolding `createKEMHeader` names loop2's result as a
freestanding `Array ByteArray × Array ByteArray` (`loop2Final`, referenced directly by loop3's own
step), never an inlined `List.foldl` term to match against `loop2Step`. This is the version that
composes with that hypothesis shape. -/
private theorem createKEMHeader_loop2_content (streamS : StreamCipher) (geom : Geometry)
    (keys : Array HopKeys) (nrHops : Nat) (final : Array ByteArray × Array ByteArray)
    (hfinal : forIn (List.range' 0 nrHops) (#[], #[])
        (fun i (st : Array ByteArray × Array ByteArray) =>
          (do
            let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
              (ofVector (keys[i]!).headerEncryptionIV)
              (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
              - (i + 1) * geom.perHopRoutingInfoLength
            let mut thisPad := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            if i > 0 then
              let prevPad := st.2[i - 1]!
              thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
                ++ thisPad.extract prevPad.size thisPad.size
            pure (ForInStep.yield (st.1.push (ks.extract 0 ksLen), st.2.push thisPad)) :
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
        (do
          let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)
          let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength
          let mut thisPad := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
          if i > 0 then
            let prevPad := st.2[i - 1]!
            thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
              ++ thisPad.extract prevPad.size thisPad.size
          pure (ForInStep.yield (st.1.push (ks.extract 0 ksLen), st.2.push thisPad)) :
            Except String (ForInStep (Array ByteArray × Array ByteArray)))) b a
        ≠ Except.ok (ForInStep.done a') := by
    intro b a a' _hb hcontra
    dsimp only at hcontra
    split at hcontra <;> simp_all [pure, Except.pure]
  obtain ⟨s, hs0, hsl, hstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
    (List.range' 0 nrHops) _ hnd (#[], #[]) final hfinal
  have hlen : (List.range' 0 nrHops).length = nrHops := by simp
  have hsl' : s nrHops = final := by rw [← hlen]; exact hsl
  have hstep' : ∀ j, j < nrHops →
      (do
        let ks := streamS.keystream (ofVector (keys[j]!).headerEncryption)
          (ofVector (keys[j]!).headerEncryptionIV)
          (geom.routingInfoLength + geom.perHopRoutingInfoLength)
        let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
          - (j + 1) * geom.perHopRoutingInfoLength
        let mut thisPad := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
        if j > 0 then
          let prevPad := (s j).2[j - 1]!
          thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
            ++ thisPad.extract prevPad.size thisPad.size
        pure (ForInStep.yield ((s j).1.push (ks.extract 0 ksLen), (s j).2.push thisPad)) :
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
      dsimp only at hstepj
      split at hstepj <;>
        · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
          rw [← hstepj]; simp [ih1, ih2]
  have hstable1 := Array.getElem!_stable_of_pushes (fun j => (s j).1) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      dsimp only at hstepj
      split at hstepj <;>
        · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
          exact ⟨_, (congrArg Prod.fst hstepj).symm⟩)
    (fun j hj => (hsize j hj).1)
  have hstable2 := Array.getElem!_stable_of_pushes (fun j => (s j).2) nrHops
    (fun j hj => by
      have hstepj := hstep' j hj
      dsimp only at hstepj
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
  dsimp only at hstepi
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

/-- **`riPadding[i]!`'s byte size**: exactly `(i+1) * perHopRoutingInfoLength` — one `perHop` for
every hop cascaded through so far, by induction on `createKEMHeader_loop2_content`'s own recursive
value formula. Needed for `hopPacket`'s overall size, since `riPadding[k-1]!` is one of its
components. -/
private theorem createKEMHeader_loop2_padsize (streamS : StreamCipher) (geom : Geometry)
    (keys : Array HopKeys) (nrHops : Nat) (final : Array ByteArray × Array ByteArray)
    (hfinal : forIn (List.range' 0 nrHops) (#[], #[])
        (fun i (st : Array ByteArray × Array ByteArray) =>
          (do
            let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
              (ofVector (keys[i]!).headerEncryptionIV)
              (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            let ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
              - (i + 1) * geom.perHopRoutingInfoLength
            let mut thisPad := ks.extract ksLen (geom.routingInfoLength + geom.perHopRoutingInfoLength)
            if i > 0 then
              let prevPad := st.2[i - 1]!
              thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
                ++ thisPad.extract prevPad.size thisPad.size
            pure (ForInStep.yield (st.1.push (ks.extract 0 ksLen), st.2.push thisPad)) :
              Except String (ForInStep (Array ByteArray × Array ByteArray)))) = Except.ok final)
    (hle : ∀ i (hi : i < nrHops),
        (i + 1) * geom.perHopRoutingInfoLength ≤ geom.routingInfoLength + geom.perHopRoutingInfoLength) :
    ∀ i (hi : i < nrHops), final.2[i]!.size = (i + 1) * geom.perHopRoutingInfoLength := by
  intro i hi
  induction i with
  | zero =>
    obtain ⟨-, hval⟩ := createKEMHeader_loop2_content streamS geom keys nrHops final hfinal 0 hi
    rw [hval]
    dsimp only
    rw [if_neg (by omega), ByteArray.size_extract, streamS.keystream_size]
    omega
  | succ i ih =>
    obtain ⟨-, hval⟩ := createKEMHeader_loop2_content streamS geom keys nrHops final hfinal (i + 1) hi
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

/-- **`createKEMHeader`'s second loop, at the content level**: `riKeyStream[i]!` and `riPadding[i]!`
spelled out exactly, the latter in terms of `riPadding[i-1]!` (already fixed by an earlier
iteration) rather than unwound all the way back to hop `0` — precisely the one-step relationship
`unwrapKEM`'s own single XOR at hop `i` needs to match against. -/
private theorem loop2_content (streamS : StreamCipher) (geom : Geometry) (keys : Array HopKeys)
    (nrHops : Nat) (final : Array ByteArray × Array ByteArray)
    (hfinal : final = (List.range' 0 nrHops).foldl (loop2Step streamS geom keys) (#[], #[]))
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
  obtain ⟨s, hs0, hsl, hstep⟩ := createKEMHeader_loop2_trace streamS geom keys nrHops
  have hsize := loop2_trace_size streamS geom keys nrHops s hs0 hstep
  have hstable1 := Array.getElem!_stable_of_pushes (fun j => (s j).1) nrHops
    (fun j hj => ⟨_, congrArg Prod.fst (hstep j hj)⟩) (fun j hj => (hsize j hj).1)
  have hstable2 := Array.getElem!_stable_of_pushes (fun j => (s j).2) nrHops
    (fun j hj => ⟨_, congrArg Prod.snd (hstep j hj)⟩) (fun j hj => (hsize j hj).2)
  have h1 : final.1[i]! = (s (i + 1)).1[i]! := by
    rw [hfinal, ← hsl]; exact hstable1 i nrHops hi (le_refl _)
  have h2 : final.2[i]! = (s (i + 1)).2[i]! := by
    rw [hfinal, ← hsl]; exact hstable2 i nrHops hi (le_refl _)
  have hpi : (s i).1.size = i := (hsize i (by omega)).1
  have hpi2 : (s i).2.size = i := (hsize i (by omega)).2
  rw [hstep i hi] at h1 h2
  unfold loop2Step at h1 h2
  dsimp only at h1 h2
  rw [getElem!_push_eq' _ _ _ hpi.symm] at h1
  rw [getElem!_push_eq' _ _ _ hpi2.symm] at h2
  refine ⟨h1, ?_⟩
  rcases Nat.eq_zero_or_pos i with hi0 | hi0
  · subst hi0; simpa using h2
  · have hfp : final.2[i - 1]! = (s i).2[i - 1]! := by
      rw [hfinal, ← hsl]
      have := hstable2 (i - 1) nrHops (by omega) (by omega)
      rwa [show i - 1 + 1 = i from by omega] at this
    dsimp only
    rw [if_pos hi0] at ⊢
    rw [if_pos hi0, ← hfp] at h2
    exact h2

private theorem createKEMHeader_loop3_step (kem : KEM) (macS : MAC) (geom : Geometry)
    (path : Array PathHop)
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
        let macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)
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
private theorem createKEMHeader_loop3_never_done (kem : KEM) (macS : MAC) (geom : Geometry)
    (path : Array PathHop)
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
        let macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)
        pure (ForInStep.yield (routingInfo, macBytes)) :
          Except String (ForInStep (ByteArray × ByteArray))) = Except.ok (ForInStep.done a')) :
    False := by
  dsimp only at hstep
  obtain ⟨riFragment, -, hstep⟩ := Except.eq_ok_of_bind_eq_ok hstep
  injection hstep with hstep
  injection hstep

/-- **The full trace of `createKEMHeader`'s third loop.** Not just the size invariant
(`createKEMHeader_loop3_step`) but the actual sequence of `(routingInfo, macBytes)` values, one
per iteration — exactly the `R(i)`/`M(i)` pair from the hand derivation this file's module doc
refers to (`s j` is `(R(nrHops - j), M(nrHops - j))`; equivalently, writing `i := nrHops - 1 - j`
for the hop processed at step `j`, `s j = (R(i+1), M(i+1))` and `s (j+1) = (R(i), M(i))`). Built
from the fully generic `List.forIn_exists_trace` plus the already-proved
`createKEMHeader_loop3_never_done`; no new induction needed here. -/
private theorem createKEMHeader_loop3_trace (kem : KEM) (macS : MAC) (geom : Geometry)
    (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (nrHops : Nat) (init final : ByteArray × ByteArray)
    (hfinal :
      forIn (List.range' 0 nrHops) init
        (fun iRev (st : ByteArray × ByteArray) =>
          (do
            let i := nrHops - 1 - iRev
            let riFragment ← kemRiFragment kem geom path kemElements st.2 nrHops i
            let routingInfo := riFragment ++ st.1
            let routingInfo := xorBytes routingInfo (riKeyStream[i]!)
            let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
              ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
            let macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)
            pure (ForInStep.yield (routingInfo, macBytes)) :
              Except String (ForInStep (ByteArray × ByteArray)))) = Except.ok final) :
    ∃ s : Nat → ByteArray × ByteArray, s 0 = init ∧ s nrHops = final ∧
      ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j)
            = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))) := by
  have hnd : ∀ (b : Nat) (a a' : ByteArray × ByteArray), b ∈ List.range' 0 nrHops →
      (fun iRev (st : ByteArray × ByteArray) =>
        (do
          let i := nrHops - 1 - iRev
          let riFragment ← kemRiFragment kem geom path kemElements st.2 nrHops i
          let routingInfo := riFragment ++ st.1
          let routingInfo := xorBytes routingInfo (riKeyStream[i]!)
          let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
            ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
          let macBytes := ofVector (macS.mac (ofVector (keys[i]!).headerMAC) mPreimage)
          pure (ForInStep.yield (routingInfo, macBytes)) :
            Except String (ForInStep (ByteArray × ByteArray)))) b a
        ≠ Except.ok (ForInStep.done a') := by
    intro b a a' _hb hcontra
    exact createKEMHeader_loop3_never_done kem macS geom path keys kemElements riKeyStream riPadding
      nrHops b a.1 a.2 a' hcontra
  obtain ⟨s, hs0, hsl, hstep⟩ := CryptWalker.Sphinx.Common.List.forIn_exists_trace
    (List.range' 0 nrHops) _ hnd init final hfinal
  refine ⟨s, hs0, by simpa using hsl, ?_⟩
  intro j hj
  have hj' : j < (List.range' 0 nrHops).length := by simpa using hj
  have hstepj := hstep j hj'
  simp only [List.getElem_range', Nat.one_mul, Nat.zero_add] at hstepj
  obtain ⟨riFragment, hriFragment, hstepj⟩ := Except.eq_ok_of_bind_eq_ok hstepj
  simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hstepj
  have h1 : (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) :=
    (congrArg Prod.fst hstepj).symm
  have h2 : (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
      (v0AD ++ kemElements[nrHops - 1 - j]!
        ++ xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!)
        ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))) :=
    (congrArg Prod.snd hstepj).symm
  exact ⟨riFragment, hriFragment, h1, by rw [h2, ← h1]⟩

/-- **Sizes along the loop3 trace**: `(s j).1` grows by exactly one `perHopRoutingInfoLength` per
step (each `riFragment` is exactly that wide, by `kemRiFragment_size`), and `(s j).2` — once at
least one step has run — is always exactly `macS.tagSize` wide, by the type of `macS.mac` alone. -/
private theorem createKEMHeader_s_size (kem : KEM) (macS : MAC) (geom : Geometry)
    (path : Array PathHop) (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray)
    (hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength)
    (hnnh : geom.nextNodeHopLength = nextNodeHopLength) (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hstep : ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty)))) :
    ∀ j (hj : j ≤ nrHops), (s j).1.size = (s 0).1.size + j * geom.perHopRoutingInfoLength ∧
      (0 < j → (s j).2.size = macS.tagSize) := by
  intro j hj
  induction j with
  | zero => simp
  | succ j ih =>
    obtain ⟨ih1, -⟩ := ih (by omega)
    obtain ⟨riFragment, hriFragment, h1, h2⟩ := hstep j (by omega)
    have hrfsize : riFragment.size = geom.perHopRoutingInfoLength :=
      kemRiFragment_size kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) (by omega)
        hperhop hnnh hknsize hksize riFragment hriFragment
    refine ⟨?_, fun _ => ?_⟩
    · rw [h1, size_xorBytes, ByteArray.size_append, hrfsize, ih1]; ring
    · rw [h2]; exact Util.Bytes.size_ofVector _

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **`createKEMHeader`, fully unfolded to content.** Packages `createKEMHeader_loop1_content`/
`createKEMHeader_loop2_content`/`createKEMHeader_loop3_trace` (plus the header/`sprpKeys` assembly
itself) behind one hypothesis, in the exact shape a successful `createKEMHeader` call actually
unfolds to — no `List.forIn_pure_yield_eq_foldl`/`ite_pure_yield` collapsing, so `loop3`'s own
per-step fact references `riKeyStream`/`riPadding` as plain array parameters, matching
`createKEMHeader_loop3_trace` directly. The single entry point the multi-hop completeness proof
builds on. -/
private theorem createKEMHeader_unfold (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray)
    (path : Array PathHop) (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (h : createKEMHeader kem macS kdfS streamS geom ephemeralSeeds filler path = .ok (hdr, sprpKeys)) :
    path.size ≠ 0 ∧ path.size ≤ geom.nrHops ∧ ephemeralSeeds.size = path.size ∧
    (geom.nrHops > path.size → filler.size = (geom.nrHops - path.size) * geom.perHopRoutingInfoLength) ∧
    ∃ (kemElements : Array ByteArray) (keys : Array HopKeys)
      (riKeyStream riPadding : Array ByteArray) (s : Nat → ByteArray × ByteArray),
      kemElements.size = path.size ∧ keys.size = path.size ∧
      riKeyStream.size = path.size ∧ riPadding.size = path.size ∧
      (∀ i (hi : i < path.size), ∃ ct ss,
        kemEncap kem (path[i]!).publicKey (ephemeralSeeds[i]!) = Except.ok (ct, ss) ∧
        kemElements[i]! = ct ∧ keys[i]! = deriveHopKeysG kdfS ss) ∧
      (∀ i (hi : i < path.size),
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
      (∀ j (hj : j < path.size), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 path.size (path.size - 1 - j)
            = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[path.size - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[path.size - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[path.size - 1 - j]! ++ (s (j + 1)).1
            ++ (if path.size - 1 - j > 0 then riPadding[path.size - 1 - j - 1]! else ByteArray.empty)))) ∧
      hdr = v0AD ++ kemElements[0]! ++ (s path.size).1 ++ (s path.size).2 ∧
      sprpKeys = Array.ofFn (fun i : Fin path.size =>
        { key := keys[i.val]!.payloadEncryption, iv := keys[i.val]!.headerEncryptionIV }) := by
  unfold createKEMHeader at h
  dsimp only at h
  split at h
  case isTrue =>
    have h' : (Except.error "sphinx: invalid path" :
        Except String (ByteArray × Array SPRPKey)) = Except.ok (hdr, sprpKeys) := h
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
          Nat.add_sub_cancel, Nat.div_one] at h
        obtain ⟨loop1Final, hLoop1, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
        obtain ⟨loop2Final, hLoop2, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
        obtain ⟨loop3Final, hLoop3, h⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
        obtain ⟨s, hs0, hsl, hstep⟩ := createKEMHeader_loop3_trace kem macS geom path loop1Final.2
          loop1Final.1 loop2Final.1 loop2Final.2 path.size _ loop3Final hLoop3
        simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h1
        have hpos : path.size ≠ 0 := h1.1
        have hgen : path.size ≤ geom.nrHops := by omega
        have heseeds : ephemeralSeeds.size = path.size := by
          by_contra hc; exact h1b hc
        have hfsize : geom.nrHops > path.size → filler.size = (geom.nrHops - path.size)
            * geom.perHopRoutingInfoLength := by
          intro hgt
          simp only [Bool.and_eq_true, decide_eq_true_eq, not_and, not_not] at h2
          exact h2 hgt
        refine ⟨hpos, hgen, heseeds, hfsize, loop1Final.1, loop1Final.2, loop2Final.1, loop2Final.2,
          s, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
        · have := CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem (List.range' 0 path.size) _
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
        · have hkeysize := CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem
            (List.range' 0 path.size) _
            (fun (a : Array ByteArray × Array HopKeys) => a.2.size) 1
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
          simpa [List.length_range'] using hkeysize
        · have := CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem (List.range' 0 path.size) _
            (fun (a : Array ByteArray × Array ByteArray) => a.1.size) 1
            (fun a a' i hi hgb => by
              split at hgb <;>
                · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
                  rw [← hgb]; simp)
            (fun a a' i hi hgb => by
              split at hgb <;> · simp_all [pure, Except.pure])
            (#[], #[]) loop2Final hLoop2
          simpa [List.length_range'] using this
        · have := CryptWalker.Sphinx.Common.List.forIn_add_of_forall_mem (List.range' 0 path.size) _
            (fun (a : Array ByteArray × Array ByteArray) => a.2.size) 1
            (fun a a' i hi hgb => by
              split at hgb <;>
                · simp only [pure, Except.pure, Except.ok.injEq, ForInStep.yield.injEq] at hgb
                  rw [← hgb]; simp)
            (fun a a' i hi hgb => by
              split at hgb <;> · simp_all [pure, Except.pure])
            (#[], #[]) loop2Final hLoop2
          simpa [List.length_range'] using this
        · exact createKEMHeader_loop1_content kem kdfS path ephemeralSeeds path.size loop1Final
            hLoop1
        · exact createKEMHeader_loop2_content streamS geom loop1Final.2 path.size loop2Final hLoop2
        · exact hs0
        · exact hstep
        · injection h with h
          have hhdreq := congrArg Prod.fst h
          simp only at hhdreq
          rw [← hhdreq, hsl]
        · injection h with h
          have hkeys := congrArg Prod.snd h
          simp only at hkeys
          rw [← hkeys]

/-- As `NIKESphinx.createHeader_hdr_size`. Generic in `macS`/`kdfS`/`streamS`: the one extra
hypothesis this needs beyond `geom.ValidForKEM kem` is `hmactag`, tying `macS`'s output width to
`Geometry`'s own fixed `macLength` constant — the one place a MAC's width is actually baked into
the wire format (the header's trailing MAC field, at a fixed offset). `kdfS`/`streamS` need no
such hypothesis: `deriveHopKeysG`/`keystream_size` compose with an arbitrary `KDF`/`StreamCipher`
regardless of their declared `keySize`/`ivSize`, since those never appear in the *type* of
`expand`/`keystream` (both take plain `ByteArray`). -/
theorem createKEMHeader_hdr_size (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray) (path : Array PathHop)
    (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (h : createKEMHeader kem macS kdfS streamS geom ephemeralSeeds filler path = .ok (hdr, sprpKeys)) :
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
          createKEMHeader_loop1_size kem kdfS path ephemeralSeeds path.size (#[], #[]) loop1Final rfl
            hLoop1
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
        have hmacsize : loop3Final.2.size = macS.tagSize := by
          refine CryptWalker.Sphinx.Common.List.forIn_const_of_forall_mem (List.range' 0 path.size) hlne
            _ (fun (a : ByteArray × ByteArray) => a.2.size) macS.tagSize ?_ ?_ _ _ hLoop3
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
          byteArray_empty_size, hmactag]
        rw [hheader, hrouting, ← hmulcombine]
        simp only [adLength, macLength]

/-- **`newKEMPacket`**. Generic in the wide-block cipher (`cipher`) as well as the header's
`macS`/`kdfS`/`streamS`. -/
def newKEMPacket (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createKEMHeader kem macS kdfS streamS geom ephemeralSeeds filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := cipher.encrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- `newKEMPacket`'s payload loop's one-step accumulator update — never fails, so (as with
`loop2Step`) its `forIn` collapses to a bare `List.foldl` under `List.forIn_pure_yield_eq_foldl`. -/
private def payloadEncryptStep (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (b : ByteArray) (iRev : Nat) : ByteArray :=
  let k := sprpKeys[sprpKeys.size - 1 - iRev]!
  cipher.encrypt k.key.toArray (ofVector k.iv) b

/-- **The full trace of `newKEMPacket`'s payload-encryption loop.** -/
private theorem newKEMPacket_payload_trace (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (init : ByteArray) :
    ∃ t : Nat → ByteArray, t 0 = init ∧
      t sprpKeys.size = (List.range' 0 sprpKeys.size).foldl (payloadEncryptStep cipher sprpKeys) init ∧
      ∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j := by
  obtain ⟨t, ht0, htl, hstep⟩ := CryptWalker.Sphinx.Common.List.foldl_exists_trace
    (List.range' 0 sprpKeys.size) (payloadEncryptStep cipher sprpKeys) init
  refine ⟨t, ht0, by simpa using htl, ?_⟩
  intro j hj
  have hj' : j < (List.range' 0 sprpKeys.size).length := by simpa using hj
  simpa using hstep j hj'

/-- **The payload-layering invariant, at the content level**: writing `payloadAt k := t
(sprpKeys.size - k)` for the trace above (so `payloadAt 0` is the fully sender-encrypted payload —
what ends up in the packet — and `payloadAt sprpKeys.size` is the all-zero-tag-prefixed plaintext),
hop `k` recovers `payloadAt (k+1)` from `payloadAt k` by decrypting with exactly *its own*
`sprpKeys[k]!` — the SPRP-layering fact `unwrapKEM`'s payload decryption at each hop needs. -/
private theorem newKEMPacket_payload_content (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (t : Nat → ByteArray)
    (hstep : ∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (k : Nat) (hk : k < sprpKeys.size) :
    t (sprpKeys.size - k) = cipher.encrypt (sprpKeys[k]!).key.toArray (ofVector (sprpKeys[k]!).iv)
      (t (sprpKeys.size - (k + 1))) := by
  have hstepk := hstep (sprpKeys.size - k - 1) (by omega)
  rw [show sprpKeys.size - k - 1 + 1 = sprpKeys.size - k from by omega] at hstepk
  unfold payloadEncryptStep at hstepk
  rw [show sprpKeys.size - 1 - (sprpKeys.size - k - 1) = k from by omega] at hstepk
  rw [hstepk, show sprpKeys.size - (k + 1) = sprpKeys.size - k - 1 from by omega]

/-- The payload trace never changes size — `cipher.encrypt` preserves length at every step. -/
private theorem newKEMPacket_payload_size_trace (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (t : Nat → ByteArray)
    (hstep : ∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j) :
    ∀ j (hj : j ≤ sprpKeys.size), (t j).size = (t 0).size := by
  intro j hj
  induction j with
  | zero => rfl
  | succ j ih =>
    rw [hstep j (by omega)]
    unfold payloadEncryptStep
    rw [cipher.encrypt_size]
    exact ih (by omega)

/-- **`newKEMPacket`, fully unfolded to content.** As `createKEMHeader_unfold`: packages
`createKEMHeader`'s own success, and the payload-encryption trace (`newKEMPacket_payload_trace`),
behind one hypothesis, in the shape a successful `newKEMPacket` call actually unfolds to. -/
private theorem newKEMPacket_unfold (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newKEMPacket kem cipher macS kdfS streamS geom ephemeralSeeds filler path payload
      = Except.ok pkt) :
    payload.size = geom.forwardPayloadLength ∧
    ∃ (hdr : ByteArray) (sprpKeys : Array SPRPKey) (t : Nat → ByteArray),
      createKEMHeader kem macS kdfS streamS geom ephemeralSeeds filler path = Except.ok (hdr, sprpKeys) ∧
      t 0 = (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload ∧
      (∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j) ∧
      pkt = hdr ++ t sprpKeys.size := by
  unfold newKEMPacket at h
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
    obtain ⟨t, ht0, htl, hstep⟩ := newKEMPacket_payload_trace cipher x.2
      ((⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload)
    refine ⟨by omega, x.1, x.2, t, hx, ht0, hstep, ?_⟩
    injection hfx with hfx
    have hfeq : (fun b a => cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray
        (ofVector x.2[x.2.size - 1 - a]!.iv) b) = payloadEncryptStep cipher x.2 := rfl
    rw [hfeq] at hfx
    rw [← hfx, htl]

/-- As `NIKESphinx.newNIKEPacket_size`. Generic in `cipher` too: `cipher.encrypt_size` replaces
`AEZ.sprpEncrypt_size` directly, no extra hypothesis needed (length preservation never depended on
`cipher.keySize`/`ivSize`, since `encrypt`'s type doesn't mention them). -/
theorem newKEMPacket_size (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (h : newKEMPacket kem cipher macS kdfS streamS geom ephemeralSeeds filler path payload = .ok pkt)
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
        (fun b a ↦ cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
        ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload) := by
      injection hfx with hfx; exact hfx.symm
    have hhdrsize := createKEMHeader_hdr_size kem macS kdfS streamS geom ephemeralSeeds filler path
      x.1 x.2 hvalid hmactag hx
    have hfoldsize := CryptWalker.Sphinx.Common.List.foldl_size_preserving (List.range' 0 x.2.size)
      (fun b a ↦ cipher.encrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
      (fun b a ↦ cipher.encrypt_size _ _ b)
      ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload)
    rw [hpkt, ByteArray.size_append, hhdrsize, hfoldsize, ByteArray.size_append, hpacket]
    simp only [byteArray_mk_size, Array.size_replicate]
    omega

/-- **The packet arriving at hop `k`** (`0 ≤ k < nrHops`), assembled from `createKEMHeader`'s
`kemElements`/`riPadding`/loop3 trace `s` and `newKEMPacket`'s payload trace `t` — writing
`R(i) := (s (nrHops - i)).1`, `M(i) := (s (nrHops - i)).2`, `P(i) := riPadding[i]!` and
`payloadAt(i) := t (nrHops - i)` (matching this file's hand-derivation module doc), `hopPacket
kemElements riPadding s t nrHops k = v0AD ++ kemElements[k]! ++ (R(k) ++ P(k-1)) ++ M(k) ++
payloadAt(k)`, with `P(-1) := empty`. At `k = 0` this is exactly `wrapKEM`'s own output
(`createKEMHeader_unfold`/`newKEMPacket_unfold`'s `hdr ++ t sprpKeys.size`, since `R(0) = (s
nrHops).1`/`M(0) = (s nrHops).2` need no padding term and `sprpKeys.size = nrHops`); at `k =
nrHops-1` it's the packet the terminal hop receives. -/
private def hopPacket (kemElements riPadding : Array ByteArray) (s : Nat → ByteArray × ByteArray)
    (t : Nat → ByteArray) (nrHops k : Nat) : ByteArray :=
  v0AD ++ kemElements[k]! ++ ((s (nrHops - k)).1 ++ (if k > 0 then riPadding[k - 1]! else ByteArray.empty))
    ++ (s (nrHops - k)).2 ++ t (nrHops - k)

/-- **`hopPacket`'s size**: exactly `geom.packetLength`, for every `k < nrHops` — the routing-info
slot (`R(k) ++ P(k-1)`) is always exactly `geom.routingInfoLength` bytes regardless of `k` (`R`
shrinks by one `perHop` per hop exactly as `P` grows by one), matching the classical Sphinx
invariant that the wire format never changes size as a packet is forwarded. -/
private theorem hopPacket_size (kem : KEM) (macS : MAC) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (hs0 : s 0 = (if geom.nrHops > nrHops then
        (⟨Array.replicate ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength) 0⟩ : ByteArray)
      else ByteArray.empty, ByteArray.empty))
    (hstep : ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hpadsize : ∀ i (hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (htsize : ∀ j (hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops) (k : Nat) (hk : k < nrHops) :
    (hopPacket kemElements riPadding s t nrHops k).size = geom.packetLength := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  have hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength := by
    rw [hs0]
    split
    · simp
    · next hc =>
      simp only [byteArray_empty_size]
      have hz : geom.nrHops - nrHops = 0 := by omega
      rw [hz, Nat.zero_mul]
  have hssize := createKEMHeader_s_size kem macS geom path keys kemElements riKeyStream riPadding
    nrHops s hperhop hnnh hknsize hksize hstep
  have hR : (s (nrHops - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength + (nrHops - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - k) (by omega)).1
  have hM : (s (nrHops - k)).2.size = macS.tagSize := (hssize (nrHops - k) (by omega)).2 (by omega)
  have hcts : kemElements[k]!.size = kem.ciphertextSize := by
    rw [getElem!_pos kemElements k (by omega)]; exact hksize k (by omega)
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

/-- **`hopPacket`'s five wire-format slices**, spelled out at the exact byte offsets `unwrapKEM`
reads them at (`geOff = 2`, `riOff = geOff + ciphertextSize`, `macOff = riOff + routingInfoLength`,
`payloadOff = macOff + macLength`) — the fact `unwrapKEM`'s own extracts need to match against a
packet built by `hopPacket`, one slice at a time. Shares `hopPacket_size`'s hypotheses and its
proof's opening moves (the `R(k)`/`M(k)` size facts). -/
private theorem hopPacket_slices (kem : KEM) (macS : MAC) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (cipher : WideBlockCipher) (sprpKeys : Array SPRPKey)
    (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (hs0 : s 0 = (if geom.nrHops > nrHops then
        (⟨Array.replicate ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength) 0⟩ : ByteArray)
      else ByteArray.empty, ByteArray.empty))
    (hstep : ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hpadsize : ∀ i (hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (htsize : ∀ j (hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops) (k : Nat) (hk : k < nrHops) :
    (hopPacket kemElements riPadding s t nrHops k).extract 0 2 = v0AD ∧
    (hopPacket kemElements riPadding s t nrHops k).extract 2 (2 + kem.ciphertextSize) = kemElements[k]! ∧
    (hopPacket kemElements riPadding s t nrHops k).extract (2 + kem.ciphertextSize)
        (2 + kem.ciphertextSize + geom.routingInfoLength)
      = (s (nrHops - k)).1 ++ (if k > 0 then riPadding[k - 1]! else ByteArray.empty) ∧
    (hopPacket kemElements riPadding s t nrHops k).extract
        (2 + kem.ciphertextSize + geom.routingInfoLength)
        (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
      = (s (nrHops - k)).2 ∧
    (hopPacket kemElements riPadding s t nrHops k).extract
        (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
        (hopPacket kemElements riPadding s t nrHops k).size
      = t (nrHops - k) := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  have hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength := by
    rw [hs0]
    split
    · simp
    · next hc =>
      simp only [byteArray_empty_size]
      have hz : geom.nrHops - nrHops = 0 := by omega
      rw [hz, Nat.zero_mul]
  have hssize := createKEMHeader_s_size kem macS geom path keys kemElements riKeyStream riPadding
    nrHops s hperhop hnnh hknsize hksize hstep
  have hR : (s (nrHops - k)).1.size
      = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength + (nrHops - k) * geom.perHopRoutingInfoLength :=
    hs0size ▸ (hssize (nrHops - k) (by omega)).1
  have hM : (s (nrHops - k)).2.size = macS.tagSize := (hssize (nrHops - k) (by omega)).2 (by omega)
  have hcts : kemElements[k]!.size = kem.ciphertextSize := by
    rw [getElem!_pos kemElements k (by omega)]; exact hksize k (by omega)
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
  generalize hCTeq : kemElements[k]! = CT at hcts ⊢
  generalize hM2eq : (s (nrHops - k)).2 = M2 at hM ⊢
  generalize hT2eq : t (nrHops - k) = T2
  have hABsize : (v0AD ++ CT).size = 2 + kem.ciphertextSize := by
    simp only [ByteArray.size_append]; rw [hv0, hcts]
  have hABCsize : (v0AD ++ CT ++ RP).size = 2 + kem.ciphertextSize + geom.routingInfoLength := by
    simp only [ByteArray.size_append]; rw [hv0, hcts, hRPsize']
  have hABCDsize : (v0AD ++ CT ++ RP ++ M2).size
      = 2 + kem.ciphertextSize + geom.routingInfoLength + macLength := by
    simp only [ByteArray.size_append]; rw [hv0, hcts, hRPsize', hM, hmactag]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rw [extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_le _ _ (by omega : (2 : Nat) ≤ (v0AD ++ CT).size),
      extract_append_of_le _ _ (by rw [hv0] : (2 : Nat) ≤ v0AD.size)]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize ≤ (v0AD ++ CT).size),
      extract_append_of_ge _ _ (by rw [hv0] : v0AD.size ≤ 2),
      show (2 : Nat) - v0AD.size = 0 from by rw [hv0],
      show 2 + kem.ciphertextSize - v0AD.size = kem.ciphertextSize from by rw [hv0]; omega]
    rw [← hcts]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize + geom.routingInfoLength
        ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize + geom.routingInfoLength
        ≤ (v0AD ++ CT ++ RP).size),
      extract_append_of_ge _ _ (by omega : (v0AD ++ CT).size ≤ 2 + kem.ciphertextSize),
      show 2 + kem.ciphertextSize - (v0AD ++ CT).size = 0 from by omega,
      show 2 + kem.ciphertextSize + geom.routingInfoLength - (v0AD ++ CT).size
        = RP.size from by omega]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_le _ _ (by omega : 2 + kem.ciphertextSize + geom.routingInfoLength + macLength
        ≤ (v0AD ++ CT ++ RP ++ M2).size),
      extract_append_of_ge _ _ (by omega : (v0AD ++ CT ++ RP).size
        ≤ 2 + kem.ciphertextSize + geom.routingInfoLength),
      show 2 + kem.ciphertextSize + geom.routingInfoLength - (v0AD ++ CT ++ RP).size = 0
        from by omega,
      show 2 + kem.ciphertextSize + geom.routingInfoLength + macLength - (v0AD ++ CT ++ RP).size
        = M2.size from by omega]
    exact ByteArray.extract_zero_size
  · rw [extract_append_of_ge _ _ (by omega :
        (v0AD ++ CT ++ RP ++ M2).size ≤ 2 + kem.ciphertextSize + geom.routingInfoLength + macLength),
      show 2 + kem.ciphertextSize + geom.routingInfoLength + macLength - (v0AD ++ CT ++ RP ++ M2).size
        = 0 from by omega,
      show (v0AD ++ CT ++ RP ++ M2 ++ T2).size - (v0AD ++ CT ++ RP ++ M2).size = T2.size
        from by simp only [ByteArray.size_append]; omega]
    exact ByteArray.extract_zero_size
/-- **The cascading-padding argument, at the byte level.** The core mathematical crux of Sphinx's
completeness (Danezis–Goldberg §3.2): given the sender's `Rk := xorBytes (riFragment ++ Rk1)
riKeyStream` (where `riKeyStream` is the exact-length prefix `ks.extract 0 ksLen` of the full
keystream `ks` requested at this hop), the *receiver*'s single XOR against the *whole* `ks`
recovers `riFragment ++ Rk1` in its first `ksLen` bytes (`xorBytes_xorBytes` cancels the
sender's own construction exactly) and reproduces `riPadding`'s own recursive definition
term-for-term in its trailing bytes (`prevPad` cascaded against `ks`'s own tail, zeros left
unchanged) — the two halves of `loop3`/`loop2`'s constructions the receiver's one XOR undoes at
once. -/
theorem cascading_xor_step (ks riFragment Rk1 prevPad : ByteArray) (ksLen perHop : Nat)
    (hks : ks.size = ksLen + prevPad.size + perHop) (hRk1 : riFragment.size + Rk1.size = ksLen) :
    (xorBytes (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen) ++ prevPad
        ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks).extract 0 ksLen
      = riFragment ++ Rk1 ∧
    (xorBytes (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen) ++ prevPad
        ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks).extract ksLen (ksLen + prevPad.size + perHop)
      = xorBytes ((ks.extract ksLen ks.size).extract 0 prevPad.size) prevPad
        ++ (ks.extract ksLen ks.size).extract prevPad.size (ks.extract ksLen ks.size).size := by
  have hzsize : (⟨Array.replicate perHop 0⟩ : ByteArray).size = perHop := Array.size_replicate
  have hRksize : (ks.extract 0 ksLen).size = ksLen := by rw [ByteArray.size_extract]; omega
  have hthisPad0size : (ks.extract ksLen ks.size).size = prevPad.size + perHop := by
    rw [ByteArray.size_extract]; omega
  have hRk_def_size : (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen)).size = ksLen := by
    rw [size_xorBytes, ByteArray.size_append]; omega
  have hprevpadle : prevPad.size ≤ (ks.extract ksLen ks.size).size := by rw [hthisPad0size]; omega
  have hRfk1size : (riFragment ++ Rk1).size = ksLen := by rw [ByteArray.size_append]; omega
  -- Abstract the two extracts as opaque values before touching `ks` itself, to avoid `rw`
  -- re-substituting `ks` inside its own extract subterms (the term-blowup trap).
  generalize hrKS : ks.extract 0 ksLen = riKeyStream at hRksize hRk_def_size ⊢
  generalize htp : ks.extract ksLen ks.size = thisPad0 at hthisPad0size hprevpadle ⊢
  have hks_eq : ks = riKeyStream ++ thisPad0 := by
    rw [← hrKS, ← htp]; exact (append_extract ks ksLen (by omega)).symm
  have hthisPad0_eq : thisPad0 = thisPad0.extract 0 prevPad.size
      ++ thisPad0.extract prevPad.size thisPad0.size :=
    (append_extract thisPad0 prevPad.size hprevpadle).symm
  have hpad2 : xorBytes (prevPad ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) thisPad0
      = xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size := by
    conv_lhs => rw [hthisPad0_eq]
    rw [xorBytes_append prevPad (⟨Array.replicate perHop 0⟩ : ByteArray)
        (thisPad0.extract 0 prevPad.size) (thisPad0.extract prevPad.size thisPad0.size)
        (by rw [ByteArray.size_extract]; omega)
        (by rw [hzsize, ByteArray.size_extract]; omega)]
    rw [xorBytes_comm_of_size_eq prevPad (thisPad0.extract 0 prevPad.size)
        (by rw [ByteArray.size_extract]; omega)]
    rw [xorBytes_zero_left perHop (thisPad0.extract prevPad.size thisPad0.size)
        (by rw [ByteArray.size_extract]; omega)]
  have hxor : xorBytes (xorBytes (riFragment ++ Rk1) riKeyStream ++ prevPad
      ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks
      = (riFragment ++ Rk1) ++ (xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size) := by
    rw [hks_eq, ByteArray.append_assoc,
      xorBytes_append (xorBytes (riFragment ++ Rk1) riKeyStream)
        (prevPad ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) riKeyStream thisPad0
        (by rw [hRk_def_size, hRksize])
        (by rw [ByteArray.size_append, hzsize, hthisPad0size])]
    rw [xorBytes_xorBytes, hpad2]
  refine ⟨?_, ?_⟩
  · rw [hxor, extract_append_le (riFragment ++ Rk1) _ (by omega : (riFragment ++ Rk1).size ≤ ksLen)]
    rw [show ksLen - (riFragment ++ Rk1).size = 0 from by omega, ByteArray.extract_same,
      ByteArray.append_empty]
  · rw [hxor, extract_append_of_ge (riFragment ++ Rk1) _
      (by omega : (riFragment ++ Rk1).size ≤ ksLen)]
    rw [show ksLen - (riFragment ++ Rk1).size = 0 from by omega,
      show ksLen + prevPad.size + perHop - (riFragment ++ Rk1).size = prevPad.size + perHop
        from by omega]
    have hpadsizeeq : (xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size).size = prevPad.size + perHop := by
      rw [ByteArray.size_append, size_xorBytes, ByteArray.size_extract, ByteArray.size_extract,
        hthisPad0size]
      omega
    rw [← hpadsizeeq]
    exact ByteArray.extract_zero_size

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapKEM`**: `Sphinx.Interface.wrap` for `KEMSphinxScheme` — `newKEMPacket`, drawing one
ephemeral seed per hop from the seed stream instead of taking them as a bare array. -/
def wrapKEM (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  match newKEMPacket kem cipher macS kdfS streamS geom seeds filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    if hsize : pkt.size = geom.packetLength then pure ⟨pkt.data, hsize⟩
    else throw "sphinx: internal error: newKEMPacket produced a wrong-sized packet"

/-- **`newKEMSURB`**. As `NIKESphinx.newNIKESURB`, over `createKEMHeader`. -/
def newKEMSURB (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32))
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createKEMHeader kem macS kdfS streamS geom ephemeralSeeds filler path
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `NIKESphinx.newNIKESURB_size`. -/
theorem newKEMSURB_size (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher)
    (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (surb surbKeys : ByteArray)
    (h : newKEMSURB kem macS kdfS streamS geom ephemeralSeeds keyPayload filler path
      = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength := by
  obtain ⟨-, -, -, -, -, hsurb⟩ := id hvalid
  unfold newKEMSURB at h
  dsimp only at h
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind] at h
  obtain ⟨x, hx, hfx⟩ := CryptWalker.Sphinx.Common.Except.eq_ok_of_bind_eq_ok h
  have hsurbeq : surb = x.1 ++ ofVector (path[0]!).id ++ ofVector keyPayload := by
    injection hfx with hfx; exact congrArg Prod.fst hfx.symm
  have hhdrsize := createKEMHeader_hdr_size kem macS kdfS streamS geom ephemeralSeeds filler path
    x.1 x.2 hvalid hmactag hx
  rw [hsurbeq, ByteArray.size_append, ByteArray.size_append, hhdrsize, hsurb,
    CryptWalker.Util.Bytes.size_ofVector, CryptWalker.Util.Bytes.size_ofVector]
  simp only [nodeIDLength, CryptWalker.Sphinx.Constants.sprpKeyMaterialLength,
    CryptWalker.Sphinx.Constants.sprpKeyLength, CryptWalker.Sphinx.Constants.sprpIVLength,
    CryptWalker.Sphinx.Constants.streamIVLength]

/-- **`wrapKEMSURB`**: `Sphinx.Interface.newSURB` for `KEMSphinxScheme` — draws one ephemeral seed
per hop plus `keyPayload` (two seeds' worth) from the seed stream. -/
def wrapKEMSURB (kem : KEM) (macS : MAC) (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry)
    (path : List PathHop) (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match newKEMSURB kem macS kdfS streamS geom seeds (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    if hsize : surb.size = geom.surbLength then pure (⟨surb.data, hsize⟩, k)
    else throw "sphinx: internal error: newKEMSURB produced a wrong-sized SURB"

/-- **`unwrapKEM`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`.
Forwarding copies the next-hop ciphertext straight out of the decrypted routing-info block —
unlike `unwrapNIKE`, no `Blind` step, since there is no group element to re-blind. Generic in the
wide-block cipher/MAC/KDF/stream cipher, matching `createKEMHeader`. -/
def unwrapKEM (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (privKey : ByteArray) (pkt : ByteArray) :
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

  let keys := deriveHopKeysG kdfS sharedSecret
  let gotMac := macS.mac (ofVector keys.headerMAC) (pkt.extract 0 macOff)
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
  b := xorBytes b (streamS.keystream (ofVector keys.headerEncryption) (ofVector keys.headerEncryptionIV) b.size)
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

set_option maxHeartbeats 1000000 in
/-- **The single-hop agreement theorem, non-terminal case.** `unwrapKEM` applied to the packet
`hopPacket ... k` arriving at hop `k` (`k+1 < nrHops`, so hop `k` forwards) reproduces
`hopPacket ... (k+1)` exactly, given the honest KEM pairing (`privKey`'s own public key is
`path[k]!`'s) and that `path[k]!`'s own commands never already contain a `null` or a
`nextNodeHop` (the well-formedness every real path satisfies: intermediate hops carry no
application-level commands of their own). Assembles `cascading_xor_step` (the routing-info/padding
XOR), `kemEncap_kemDecap_of_honest` (the KEM round trip), `kemRiFragment_content_nonterminal` (what
`cmdBuf`/`nextCiphertext` parse back to), and `newKEMPacket_payload_content` (the SPRP payload
layering) against `unwrapKEM`'s own do-block, one step at a time. -/
theorem unwrapKEM_hopPacket_nonterminal (kem : KEM) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey) (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (hs0 : s 0 = (if geom.nrHops > nrHops then
        (⟨Array.replicate ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength) 0⟩ : ByteArray)
      else ByteArray.empty, ByteArray.empty))
    (hstep : ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hpadsize : ∀ i (hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (hriKScontent : ∀ i (hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength))
    (hriPadcontent : ∀ i (hi : i < nrHops), riPadding[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
           ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
       else thisPad0))
    (hkeyscontent : ∀ i (hi : i < nrHops), ∃ seed ss,
        kemEncap kem (path[i]!).publicKey seed = Except.ok (kemElements[i]!, ss) ∧
        keys[i]! = deriveHopKeysG kdfS ss)
    (htsize : ∀ j (hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (htstep : ∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
    (hsprpkey : ∀ i (hi : i < sprpKeys.size), (sprpKeys[i]'hi).key = keys[i]!.payloadEncryption ∧
        (sprpKeys[i]'hi).iv = keys[i]!.headerEncryptionIV)
    (hsprp : sprpKeys.size = nrHops) (hgen : nrHops ≤ geom.nrHops)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (k : Nat) (hk : k + 1 < nrHops)
    (hcmdnn : ∀ c ∈ (path[k]!).commands, c ≠ RoutingCommand.null)
    (hcmdnh : ∀ c ∈ (path[k]!).commands, ∀ id m, c ≠ RoutingCommand.nextNodeHop id m)
    (privKey : ByteArray) (hpp : kemSelfPublicKeyBytes kem privKey = (path[k]!).publicKey) :
    ∃ (replayTag : Vector UInt8 32) (cmds : List RoutingCommand)
      (hnewsize : (hopPacket kemElements riPadding s t nrHops (k + 1)).size
        = (hopPacket kemElements riPadding s t nrHops k).size),
      unwrapKEM kem cipher macS kdfS streamS geom privKey
          (hopPacket kemElements riPadding s t nrHops k)
        = Except.ok (none, replayTag, cmds,
            some ⟨(hopPacket kemElements riPadding s t nrHops (k + 1)).data, hnewsize⟩) ∧
      cmds = (path[k]!).commands
        ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)] := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  -- The honest KEM round trip at hop `k`.
  obtain ⟨seed, ss, hencap, hkeyseq⟩ := hkeyscontent k (by omega)
  have hdecap : kemDecap kem privKey kemElements[k]! = Except.ok ss :=
    kemEncap_kemDecap_of_honest kem privKey seed kemElements[k]! ss (by rw [hpp]; exact hencap)
  -- The loop3 trace's step at hop `k` (`j := nrHops - 1 - k`).
  have hj1 : nrHops - 1 - k < nrHops := by omega
  obtain ⟨riFragment, hriFragment0, hR1, hM1⟩ := hstep (nrHops - 1 - k) hj1
  have hidx : nrHops - 1 - (nrHops - 1 - k) = k := by omega
  rw [hidx] at hriFragment0 hR1 hM1
  have hidx2 : nrHops - 1 - k + 1 = nrHops - k := by omega
  rw [hidx2] at hR1 hM1
  -- `kemRiFragment`'s content at hop `k`, non-terminal.
  have hterm : k ≠ nrHops - 1 := by omega
  obtain ⟨hcmdEq, hctEq⟩ := kemRiFragment_content_nonterminal kem geom path kemElements
    (s (nrHops - 1 - k)).2 nrHops k (by omega) hterm hperhop hnnh hknsize hksize hcmdnn
    riFragment hriFragment0
  have hrfsize : riFragment.size = geom.perHopRoutingInfoLength :=
    kemRiFragment_size kem geom path kemElements (s (nrHops - 1 - k)).2 nrHops k (by omega)
      hperhop hnnh hknsize hksize riFragment hriFragment0
  -- Sizes needed for `cascading_xor_step`.
  have hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength := by
    rw [hs0]
    split
    · simp
    · next hc =>
      simp only [byteArray_empty_size]
      rw [show geom.nrHops - nrHops = 0 from by omega, Nat.zero_mul]
  have hssize := createKEMHeader_s_size kem macS geom path keys kemElements riKeyStream riPadding
    nrHops s hperhop hnnh hknsize hksize hstep
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
  have hRk1_hyp : riFragment.size + (s (nrHops - 1 - k)).1.size
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
    riFragment (s (nrHops - 1 - k)).1 (if k > 0 then riPadding[k - 1]! else ByteArray.empty)
    ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (k + 1) * geom.perHopRoutingInfoLength)
    geom.perHopRoutingInfoLength hks_hyp hRk1_hyp
  rw [hriKScontent k (by omega)] at hR1
  -- `R(k)` is the routing-info+padding slot the receiver actually reads off `hopPacket ... k`.
  set ks := streamS.keystream (ofVector keys[k]!.headerEncryption)
    (ofVector keys[k]!.headerEncryptionIV) (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    with hksdef
  set ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    - (k + 1) * geom.perHopRoutingInfoLength with hksLendef
  set prevPad := (if k > 0 then riPadding[k - 1]! else ByteArray.empty) with hprevPaddef
  -- The receiver's own XOR-decrypted buffer `b`.
  set b := xorBytes ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)) ks with hbdef
  rw [← hR1] at hxor
  have hcmdBuf : b.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      = riFragment.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize) := by
    have h1 : (b.extract 0 ksLen).extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
        = b.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize) := by
      rw [ByteArray.extract_extract]
      congr 1
      omega
    rw [← h1, hxor.1, extract_append_of_le riFragment _ (by omega : geom.perHopRoutingInfoLength
      - kem.ciphertextSize ≤ riFragment.size)]
  have hnextCT : b.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      geom.perHopRoutingInfoLength
      = riFragment.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
        geom.perHopRoutingInfoLength := by
    have h1 : (b.extract 0 ksLen).extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
        geom.perHopRoutingInfoLength
        = b.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize)
          geom.perHopRoutingInfoLength := by
      rw [ByteArray.extract_extract]
      congr 1 <;> omega
    rw [← h1, hxor.1, extract_append_of_le riFragment _ (le_of_eq hrfsize.symm)]
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
    rw [← h1, hxor.1, extract_append_of_ge riFragment _ (le_of_eq hrfsize)]
    rw [show geom.perHopRoutingInfoLength - riFragment.size = 0 from by omega,
      show ksLen - riFragment.size = (s (nrHops - 1 - k)).1.size from by omega]
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
  have hslices := hopPacket_slices kem macS geom path keys kemElements riKeyStream riPadding
    cipher sprpKeys nrHops s t hvalid hmactag hs0 hstep hknsize hksize hpadsize htsize ht0size
    hsprp hgen k (by omega)
  obtain ⟨hslice0, hslice1, hslice2, hslice3, hslice4⟩ := hslices
  -- The MAC-check preimage: `pkt.extract 0 macOff` is exactly `hM1`'s own `mPreimage`.
  have hpreimage : (hopPacket kemElements riPadding s t nrHops k).extract 0
      (2 + kem.ciphertextSize + geom.routingInfoLength)
      = v0AD ++ kemElements[k]! ++ (s (nrHops - k)).1 ++ prevPad := by
    rw [ByteArray.extract_eq_extract_append_extract (2 + kem.ciphertextSize) (by omega) (by omega),
      ByteArray.extract_eq_extract_append_extract 2 (by omega) (by omega),
      hslice0, hslice1, hslice2, ← hprevPaddef]
    simp only [ByteArray.append_assoc]
  have hgotMac : ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket kemElements riPadding s t nrHops k).extract 0
        (2 + kem.ciphertextSize + geom.routingInfoLength)))
      = (s (nrHops - k)).2 := by
    rw [hpreimage]; exact hM1.symm
  -- The overall packet size and the truncation/version checks.
  have hpktsize : (hopPacket kemElements riPadding s t nrHops k).size = geom.packetLength :=
    hopPacket_size kem macS geom path keys kemElements riKeyStream riPadding cipher sprpKeys
      nrHops s t hvalid hmactag hs0 hstep hknsize hksize hpadsize htsize ht0size hsprp hgen k
      (by omega)
  obtain ⟨hnnh', hperhopEq', hrouting', hheader', hpacket', -⟩ := id hvalid
  have hadL : adLength = 2 := rfl
  have hmacL : macLength = 32 := rfl
  have hpayoff : 2 + kem.ciphertextSize + geom.routingInfoLength + macLength = geom.headerLength := by
    rw [hheader']; omega
  have hnottrunc : ¬ (hopPacket kemElements riPadding s t nrHops k).size
      < 2 + kem.ciphertextSize + geom.routingInfoLength + macLength := by
    rw [hpktsize, hpayoff, hpacket']; omega
  unfold unwrapKEM
  dsimp only
  rw [dif_neg hnottrunc]
  have hversion : ¬ (((hopPacket kemElements riPadding s t nrHops k).extract 0 2).data
      ≠ v0AD.data) := by rw [hslice0]; simp
  rw [if_neg hversion, hslice1]
  dsimp only [Bind.bind, Except.bind]
  rw [hdecap]
  dsimp only
  simp only [← hkeyseq]
  have hmacpass : ¬ ((ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket kemElements riPadding s t nrHops k).extract 0
        (2 + kem.ciphertextSize + geom.routingInfoLength)))).data
      ≠ ((hopPacket kemElements riPadding s t nrHops k).extract
          (2 + kem.ciphertextSize + geom.routingInfoLength)
          (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)).data) := by
    rw [hgotMac, hslice3]; simp
  rw [if_neg hmacpass]
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
  -- The next-hop KEM ciphertext.
  have hnextCiphertext : ofVector (toVecN kem.ciphertextSize
      (b.extract (geom.perHopRoutingInfoLength - kem.ciphertextSize) geom.perHopRoutingInfoLength))
      = kemElements[k + 1]! := by
    rw [hnextCT, hctEq]
    exact ofVector_toVecN _ (by rw [getElem!_pos kemElements (k + 1) (by omega)]; exact hksize (k + 1) (by omega))
  -- The forwarded MAC.
  have hM2size : (s (nrHops - 1 - k)).2.size = 32 := by
    have hssize2 := createKEMHeader_s_size kem macS geom path keys kemElements riKeyStream riPadding
      nrHops s hperhop hnnh hknsize hksize hstep
    rw [(hssize2 (nrHops - 1 - k) (by omega)).2 (by omega), hmactag]
    rfl
  have hnextMac : ofVector (toVec32 (s (nrHops - 1 - k)).2) = (s (nrHops - 1 - k)).2 :=
    ofVector_toVec32 _ hM2size
  -- The payload SPRP layering: this hop peels its own outermost encryption layer.
  have hpayloadstep := newKEMPacket_payload_content cipher sprpKeys t htstep k (by omega)
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
        (if ((hopPacket kemElements riPadding s t nrHops k).extract
              (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
              (hopPacket kemElements riPadding s t nrHops k).size).size > 0
          then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
            ((hopPacket kemElements riPadding s t nrHops k).extract
              (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
              (hopPacket kemElements riPadding s t nrHops k).size)
          else (hopPacket kemElements riPadding s t nrHops k).extract
            (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
            (hopPacket kemElements riPadding s t nrHops k).size).size > 0
      then
        if ((hopPacket kemElements riPadding s t nrHops k).extract
              (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
              (hopPacket kemElements riPadding s t nrHops k).size).size > 0
        then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
          ((hopPacket kemElements riPadding s t nrHops k).extract
            (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
            (hopPacket kemElements riPadding s t nrHops k).size)
        else (hopPacket kemElements riPadding s t nrHops k).extract
          (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
          (hopPacket kemElements riPadding s t nrHops k).size
      else (hopPacket kemElements riPadding s t nrHops k).extract
        (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
        (hopPacket kemElements riPadding s t nrHops k).size)
      = t (nrHops - 1 - k) := by
    rw [show nrHops - (k + 1) = nrHops - 1 - k from by omega] at hpayloadstep
    have hxsize16 : 16 ≤ (t (nrHops - 1 - k)).size := by rw [hprevsize]; omega
    have hxpos : 0 < (t (nrHops - 1 - k)).size := by omega
    have hencsize : 0 < (cipher.encrypt keys[k]!.payloadEncryption.toArray
        (ofVector keys[k]!.headerEncryptionIV) (t (nrHops - 1 - k))).size := by
      rw [cipher.encrypt_size]; omega
    simp only [hslice4, hpayloadstep]
    rw [cipher.roundTrip _ _ _ hxsize16, if_pos hencsize, if_pos hxpos]
  simp only [hnextCiphertext, hnewRI, hnextMac, hnewPayload]
  have hpktsize' : (hopPacket kemElements riPadding s t nrHops (k + 1)).size = geom.packetLength :=
    hopPacket_size kem macS geom path keys kemElements riKeyStream riPadding cipher sprpKeys
      nrHops s t hvalid hmactag hs0 hstep hknsize hksize hpadsize htsize ht0size hsprp hgen (k + 1)
      (by omega)
  have hnewsize_pf : (hopPacket kemElements riPadding s t nrHops (k + 1)).size
      = (hopPacket kemElements riPadding s t nrHops k).size := by
    rw [hpktsize', hpktsize]
  have hpkteq : v0AD ++ kemElements[k + 1]! ++ ((s (nrHops - 1 - k)).1 ++ riPadding[k]!)
      ++ (s (nrHops - 1 - k)).2 ++ t (nrHops - 1 - k) = hopPacket kemElements riPadding s t nrHops (k + 1) := by
    unfold hopPacket
    rw [show nrHops - (k + 1) = nrHops - 1 - k from by omega, if_pos (by omega : k + 1 > 0),
      show k + 1 - 1 = k from by omega]
  refine ⟨sha512_256 kemElements[k]!,
    (path[k]!).commands ++ [RoutingCommand.nextNodeHop (path[k + 1]!).id (toVec32 (s (nrHops - 1 - k)).2)],
    hnewsize_pf, ?_, rfl⟩
  simp only [pure, Except.pure, hpkteq]

set_option maxHeartbeats 4000000 in
/-- **The single-hop agreement theorem, terminal case.** `unwrapKEM` applied to the packet
`hopPacket ... k` arriving at the terminal hop `k` (`k + 1 = nrHops`) recovers the original
`payload` exactly, given the honest KEM pairing and that `path[k]!`'s own commands never
already contain a `null`, `nextNodeHop`, or `surbReply` (the well-formedness a real recipient
hop satisfies — no forwarding, no reply commands of its own), plus that the payload-encryption
trace's base case `t 0` is exactly `newKEMPacket`'s own starting buffer: a zero tag of
`geom.payloadTagLength` bytes followed by `payload`. Assembles the same pieces as
`unwrapKEM_hopPacket_nonterminal` for the routing-info/MAC portion, then `kemRiFragment_content_terminal`
and `newKEMPacket_payload_content` for the payload, closing with the zero-tag check. -/
theorem unwrapKEM_hopPacket_terminal (kem : KEM) (cipher : WideBlockCipher) (macS : MAC)
    (kdfS : KDF) (streamS : StreamCipher) (geom : Geometry) (path : Array PathHop)
    (keys : Array HopKeys) (kemElements riKeyStream riPadding : Array ByteArray)
    (sprpKeys : Array SPRPKey) (nrHops : Nat) (s : Nat → ByteArray × ByteArray) (t : Nat → ByteArray)
    (hvalid : geom.ValidForKEM kem) (hmactag : macS.tagSize = macLength)
    (hs0 : s 0 = (if geom.nrHops > nrHops then
        (⟨Array.replicate ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength) 0⟩ : ByteArray)
      else ByteArray.empty, ByteArray.empty))
    (hstep : ∀ j (hj : j < nrHops), ∃ riFragment,
        kemRiFragment kem geom path kemElements (s j).2 nrHops (nrHops - 1 - j) = Except.ok riFragment ∧
        (s (j + 1)).1 = xorBytes (riFragment ++ (s j).1) (riKeyStream[nrHops - 1 - j]!) ∧
        (s (j + 1)).2 = ofVector (macS.mac (ofVector (keys[nrHops - 1 - j]!).headerMAC)
          (v0AD ++ kemElements[nrHops - 1 - j]! ++ (s (j + 1)).1
            ++ (if nrHops - 1 - j > 0 then riPadding[nrHops - 1 - j - 1]! else ByteArray.empty))))
    (hknsize : kemElements.size = nrHops)
    (hksize : ∀ j (hj : j < kemElements.size), (kemElements[j]'hj).size = kem.ciphertextSize)
    (hpadsize : ∀ i (hi : i < nrHops), riPadding[i]!.size = (i + 1) * geom.perHopRoutingInfoLength)
    (hriKScontent : ∀ i (hi : i < nrHops),
        riKeyStream[i]! = (streamS.keystream (ofVector (keys[i]!).headerEncryption)
            (ofVector (keys[i]!).headerEncryptionIV)
            (geom.routingInfoLength + geom.perHopRoutingInfoLength)).extract 0
          ((geom.routingInfoLength + geom.perHopRoutingInfoLength)
            - (i + 1) * geom.perHopRoutingInfoLength))
    (hriPadcontent : ∀ i (hi : i < nrHops), riPadding[i]! =
      (let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
       let ks := streamS.keystream (ofVector (keys[i]!).headerEncryption)
         (ofVector (keys[i]!).headerEncryptionIV) totalRiLen
       let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
       let thisPad0 := ks.extract ksLen totalRiLen
       if i > 0 then
         xorBytes (thisPad0.extract 0 riPadding[i - 1]!.size) riPadding[i - 1]!
           ++ thisPad0.extract riPadding[i - 1]!.size thisPad0.size
       else thisPad0))
    (hkeyscontent : ∀ i (hi : i < nrHops), ∃ seed ss,
        kemEncap kem (path[i]!).publicKey seed = Except.ok (kemElements[i]!, ss) ∧
        keys[i]! = deriveHopKeysG kdfS ss)
    (htsize : ∀ j (hj : j ≤ sprpKeys.size), (t j).size = (t 0).size)
    (ht0size : (t 0).size = geom.payloadTagLength + geom.forwardPayloadLength)
    (htstep : ∀ j (hj : j < sprpKeys.size), t (j + 1) = payloadEncryptStep cipher sprpKeys (t j) j)
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
    (privKey : ByteArray) (hpp : kemSelfPublicKeyBytes kem privKey = (path[k]!).publicKey) :
    unwrapKEM kem cipher macS kdfS streamS geom privKey
        (hopPacket kemElements riPadding s t nrHops k)
      = Except.ok (some payload, sha512_256 kemElements[k]!, (path[k]!).commands, none) := by
  obtain ⟨hnnh, hperhopEq, hrouting, hheader, hpacket, -⟩ := id hvalid
  have hperhop : geom.nextNodeHopLength + kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  -- The honest KEM round trip at hop `k`.
  obtain ⟨seed, ss, hencap, hkeyseq⟩ := hkeyscontent k (by omega)
  have hdecap : kemDecap kem privKey kemElements[k]! = Except.ok ss :=
    kemEncap_kemDecap_of_honest kem privKey seed kemElements[k]! ss (by rw [hpp]; exact hencap)
  -- The loop3 trace's step at hop `k` (`j := nrHops - 1 - k = 0`).
  have hj1 : nrHops - 1 - k < nrHops := by omega
  obtain ⟨riFragment, hriFragment0, hR1, hM1⟩ := hstep (nrHops - 1 - k) hj1
  have hidx : nrHops - 1 - (nrHops - 1 - k) = k := by omega
  rw [hidx] at hriFragment0 hR1 hM1
  have hidx2 : nrHops - 1 - k + 1 = nrHops - k := by omega
  rw [hidx2] at hR1 hM1
  -- `kemRiFragment`'s content at hop `k`, terminal.
  have hterm : k = nrHops - 1 := by omega
  have hcle : kem.ciphertextSize ≤ geom.perHopRoutingInfoLength := by omega
  obtain ⟨hcmdEq, hzeroTail⟩ := kemRiFragment_content_terminal kem geom path kemElements
    (s (nrHops - 1 - k)).2 nrHops k (by omega) hterm hcle hcmdnn riFragment hriFragment0
  have hrfsize : riFragment.size = geom.perHopRoutingInfoLength :=
    kemRiFragment_size kem geom path kemElements (s (nrHops - 1 - k)).2 nrHops k (by omega)
      hperhop hnnh hknsize hksize riFragment hriFragment0
  -- Sizes needed for `cascading_xor_step`.
  have hs0size : (s 0).1.size = (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength := by
    rw [hs0]
    split
    · simp
    · next hc =>
      simp only [byteArray_empty_size]
      rw [show geom.nrHops - nrHops = 0 from by omega, Nat.zero_mul]
  have hssize := createKEMHeader_s_size kem macS geom path keys kemElements riKeyStream riPadding
    nrHops s hperhop hnnh hknsize hksize hstep
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
  have hRk1_hyp : riFragment.size + (s (nrHops - 1 - k)).1.size
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
    riFragment (s (nrHops - 1 - k)).1 (if k > 0 then riPadding[k - 1]! else ByteArray.empty)
    ((geom.routingInfoLength + geom.perHopRoutingInfoLength) - (k + 1) * geom.perHopRoutingInfoLength)
    geom.perHopRoutingInfoLength hks_hyp hRk1_hyp
  rw [hriKScontent k (by omega)] at hR1
  -- `R(k)` is the routing-info+padding slot the receiver actually reads off `hopPacket ... k`.
  set ks := streamS.keystream (ofVector keys[k]!.headerEncryption)
    (ofVector keys[k]!.headerEncryptionIV) (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    with hksdef
  set ksLen := (geom.routingInfoLength + geom.perHopRoutingInfoLength)
    - (k + 1) * geom.perHopRoutingInfoLength with hksLendef
  set prevPad := (if k > 0 then riPadding[k - 1]! else ByteArray.empty) with hprevPaddef
  -- The receiver's own XOR-decrypted buffer `b`.
  set b := xorBytes ((s (nrHops - k)).1 ++ prevPad
      ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)) ks with hbdef
  rw [← hR1] at hxor
  have hcmdBuf : b.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
      = riFragment.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize) := by
    have h1 : (b.extract 0 ksLen).extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize)
        = b.extract 0 (geom.perHopRoutingInfoLength - kem.ciphertextSize) := by
      rw [ByteArray.extract_extract]
      congr 1
      omega
    rw [← h1, hxor.1, extract_append_of_le riFragment _ (by omega : geom.perHopRoutingInfoLength
      - kem.ciphertextSize ≤ riFragment.size)]
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
  have hslices := hopPacket_slices kem macS geom path keys kemElements riKeyStream riPadding
    cipher sprpKeys nrHops s t hvalid hmactag hs0 hstep hknsize hksize hpadsize htsize ht0size
    hsprp hgen k (by omega)
  obtain ⟨hslice0, hslice1, hslice2, hslice3, hslice4⟩ := hslices
  -- The MAC-check preimage: `pkt.extract 0 macOff` is exactly `hM1`'s own `mPreimage`.
  have hpreimage : (hopPacket kemElements riPadding s t nrHops k).extract 0
      (2 + kem.ciphertextSize + geom.routingInfoLength)
      = v0AD ++ kemElements[k]! ++ (s (nrHops - k)).1 ++ prevPad := by
    rw [ByteArray.extract_eq_extract_append_extract (2 + kem.ciphertextSize) (by omega) (by omega),
      ByteArray.extract_eq_extract_append_extract 2 (by omega) (by omega),
      hslice0, hslice1, hslice2, ← hprevPaddef]
    simp only [ByteArray.append_assoc]
  have hgotMac : ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket kemElements riPadding s t nrHops k).extract 0
        (2 + kem.ciphertextSize + geom.routingInfoLength)))
      = (s (nrHops - k)).2 := by
    rw [hpreimage]; exact hM1.symm
  -- The overall packet size and the truncation/version checks.
  have hpktsize : (hopPacket kemElements riPadding s t nrHops k).size = geom.packetLength :=
    hopPacket_size kem macS geom path keys kemElements riKeyStream riPadding cipher sprpKeys
      nrHops s t hvalid hmactag hs0 hstep hknsize hksize hpadsize htsize ht0size hsprp hgen k
      (by omega)
  obtain ⟨hnnh', hperhopEq', hrouting', hheader', hpacket', -⟩ := id hvalid
  have hadL : adLength = 2 := rfl
  have hmacL : macLength = 32 := rfl
  have hpayoff : 2 + kem.ciphertextSize + geom.routingInfoLength + macLength = geom.headerLength := by
    rw [hheader']; omega
  have hnottrunc : ¬ (hopPacket kemElements riPadding s t nrHops k).size
      < 2 + kem.ciphertextSize + geom.routingInfoLength + macLength := by
    rw [hpktsize, hpayoff, hpacket']; omega
  unfold unwrapKEM
  dsimp only
  rw [dif_neg hnottrunc]
  have hversion : ¬ (((hopPacket kemElements riPadding s t nrHops k).extract 0 2).data
      ≠ v0AD.data) := by rw [hslice0]; simp
  rw [if_neg hversion, hslice1]
  dsimp only [Bind.bind, Except.bind]
  rw [hdecap]
  dsimp only
  simp only [← hkeyseq]
  have hmacpass : ¬ ((ofVector (macS.mac (ofVector keys[k]!.headerMAC)
      ((hopPacket kemElements riPadding s t nrHops k).extract 0
        (2 + kem.ciphertextSize + geom.routingInfoLength)))).data
      ≠ ((hopPacket kemElements riPadding s t nrHops k).extract
          (2 + kem.ciphertextSize + geom.routingInfoLength)
          (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)).data) := by
    rw [hgotMac, hslice3]; simp
  rw [if_neg hmacpass]
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
  have hpayloadstep := newKEMPacket_payload_content cipher sprpKeys t htstep k (by omega)
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
  have hdecPayloadEq : (if ((hopPacket kemElements riPadding s t nrHops k).extract
        (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
        (hopPacket kemElements riPadding s t nrHops k).size).size > 0
      then cipher.decrypt keys[k]!.payloadEncryption.toArray (ofVector keys[k]!.headerEncryptionIV)
        ((hopPacket kemElements riPadding s t nrHops k).extract
          (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
          (hopPacket kemElements riPadding s t nrHops k).size)
      else (hopPacket kemElements riPadding s t nrHops k).extract
        (2 + kem.ciphertextSize + geom.routingInfoLength + macLength)
        (hopPacket kemElements riPadding s t nrHops k).size) = t 0 := by
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
  simp only [pure, Except.pure, hpayloadEq, Bool.false_eq_true, if_false]

/-- As `NIKESphinx.wrapNIKE_unwrapNIKE_complete`: `KEMSphinxScheme`'s witness for
`Sphinx.Interface.unwrap_complete`. Generic over the wide-block cipher/MAC/KDF/stream cipher, not
just the `KEM` — never AEZ/HMAC-SHA256/HKDF/AES-CTR specifics, only `cipher`/`macS`/`kdfS`/
`streamS`'s own fields, as `wrapKEM`/`unwrapKEM` themselves now are. -/
axiom wrapKEM_unwrapKEM_complete (kem : KEM) (cipher : WideBlockCipher) (macS : MAC) (kdfS : KDF)
    (streamS : StreamCipher) (geom : Geometry) (path : List PathHop)
    (privKeys : List ByteArray) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (kemSelfPublicKeyBytes kem) →
    wrapKEM kem cipher macS kdfS streamS geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapKEM kem cipher macS kdfS streamS geom) privKeys (ofVector pkt)
      = .ok (some (ofVector payload))

structure KEMSphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
  kem : KEM
  /-- **Not wrap-resistant** — the inverse of `NIKESphinxScheme.wrap_resistant`: a known-key
  adversary hits any target routing-info block with certainty, not merely `1/N`. See
  `unwrapKEM_routingInfoBlock_not_wrap_resistant` below for why. Stated against `stream` (this very
  instance's own field, from the base `Sphinx`), not a hardcoded stream cipher — the fact holds
  for *any* `StreamCipher`, since `xorBytes_achieves_any_target` never needed `keystream_size`. -/
  not_wrap_resistant : ∀ (key iv target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (stream.keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (stream.keystream key iv target.size) target

/-- Build a `KEMSphinxScheme` from any `KEM` at all — total, no `Except`. -/
def kemSphinxSchemeOf (kem : KEM) (geom : Geometry) : KEMSphinxScheme :=
  let cipher := CryptWalker.Sphinx.Crypto.WideBlockCipher.aez
  let macS := CryptWalker.Sphinx.Crypto.MAC.hmacSha256MAC
  let kdfS := CryptWalker.Sphinx.Crypto.GenericKDF.hkdfSha256Expand
  let streamS := CryptWalker.Sphinx.Crypto.StreamCipher.aes256CTR
  { State := SeedStream
    PrivateKey := ByteArray
    Command := RoutingCommand
    geometry := geom
    stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
    cipher := cipher
    mac    := macS
    kdf    := kdfS
    stream := streamS
    derivePublicKey := kemSelfPublicKeyBytes kem
    wrap := wrapKEM kem cipher macS kdfS streamS geom
    unwrap := unwrapKEM kem cipher macS kdfS streamS geom
    newSURB := wrapKEMSURB kem macS kdfS streamS geom
    newPacketFromSURB := fun surb payload =>
      CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
    unwrap_complete := wrapKEM_unwrapKEM_complete kem cipher macS kdfS streamS geom
    kem := kem
    not_wrap_resistant := fun key iv target =>
      xorBytes_achieves_any_target (streamS.keystream key iv target.size) target }

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
theorem unwrapKEM_routingInfoBlock_not_wrap_resistant (streamS : StreamCipher) (key iv : ByteArray)
    (target : ByteArray) :
    ∃ raw : ByteArray, xorBytes raw (streamS.keystream key iv target.size) = target :=
  xorBytes_achieves_any_target (streamS.keystream key iv target.size) target

end CryptWalker.Sphinx.KEMSphinx
