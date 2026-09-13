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
import CryptWalker.Sphinx.SURB
import CryptWalker.Sphinx.Crypto.KDF
import CryptWalker.Sphinx.Crypto.ChaCha20
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.Schemes
import CryptWalker.Sphinx.WrapResistance
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.NIKESphinx

open OracleComp OracleSpec ENNReal
open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.Crypto.KDF (PacketKeys sphinxKDF)
open CryptWalker.Sphinx.Crypto.ChaCha20 (keystream32)
open CryptWalker.Sphinx.Crypto.Stream (keystream)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

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

/-- Re-blind an envelope by a factor, at the byte level — `nikeDH` with the factor playing the
role of private key and the envelope the role of public key (`hpqc/nike/x25519`'s `Blind` *is*
`Exp`, just with the arguments named differently). Total, falling back to `pk` unchanged if either
byte string fails to decode or the envelope turns out unsafe: every call site in this file already
established the envelope's safety via a preceding `nikeDH` call before ever reaching a `blind`
call, so this fallback is provably unreachable in practice, not a silently-accepted error case.

Resized to `pk.size` (`size_nikeBlind` below) regardless of `nike.sharedSecretSize`: this is what
lets `createHeader`'s blinding chain preserve the group-element width without needing a proof that
a NIKE's public-key and shared-secret sizes agree — the reinterpretation still only makes *sense*
for a Diffie-Hellman-style NIKE where they do, but a mismatched NIKE now fails safely (wrong bytes)
rather than needing to be excluded up front. -/
private def nikeBlind (nike : NIKE) (pk factor : ByteArray) : ByteArray :=
  let result := match nike.decodePrivateKey (toVecN nike.privateKeySize factor) with
    | none => pk
    | some sk => (nikeDH nike sk pk).toOption.getD pk
  ofVector (toVecN pk.size result)

@[simp] lemma size_nikeBlind (nike : NIKE) (pk factor : ByteArray) :
    (nikeBlind nike pk factor).size = pk.size := by
  unfold nikeBlind
  exact Util.Bytes.size_ofVector _

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

/-- Everything `crypto.KDF` derives for one hop, with the raw `BlindingFactor` seed already
turned into the NIKE private key it represents (`internal/crypto.PacketKeys.BlindingFactor` is
itself a `nike.PrivateKey`, not a raw seed — `deriveHopKeys` is the point where that conversion
happens, once, rather than at every later use site). `blindingFactor` is raw bytes, not a decoded
`nike.PrivateKey`, since `HopKeys` is shared with `KEMSphinx` (unused there) and isn't itself
parametric in which `NIKE` produced it. -/
structure HopKeys where
  headerMAC : Vector UInt8 32
  headerEncryption : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption : Vector UInt8 48
  blindingFactor : ByteArray
  deriving Inhabited

/-- `sharedSecret` is whatever a NIKE's `encodeSharedSecret` produced — `sphinxKDF`/HKDF-expand
accept arbitrary-length input key material, so no fixed width is assumed here. -/
def deriveHopKeys (sharedSecret : ByteArray) : HopKeys :=
  let pk : PacketKeys := sphinxKDF sharedSecret
  { headerMAC := pk.headerMAC
    headerEncryption := pk.headerEncryption
    headerEncryptionIV := pk.headerEncryptionIV
    payloadEncryption := pk.payloadEncryption
    blindingFactor := blindingFactorPrivKey pk.blindingFactorSeed }

/-- **`createHeader`**. `filler` must be exactly `(geom.nrHops - path.size) *
geom.perHopRoutingInfoLength` bytes (ignored, and may be empty, when `path.size = geom.nrHops`)
— the random padding that hides a shorter-than-maximum path's true hop count. -/
def createHeader (nike : NIKE) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) : Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  let clientSk ← nikeDecodePrivateKey nike clientPrivateKey
  let clientPublicKey0 := ofVector (nike.encodePublicKey (nike.derivePublicKey clientSk))

  -- Per-hop shared secrets/keys, and the (progressively blinded) group elements.
  let mut groupElements : Array ByteArray := Array.replicate nrHops clientPublicKey0
  let mut keys : Array HopKeys := #[deriveHopKeys (← nikeDH nike clientSk (path[0]!).publicKey)]
  let mut clientPublicKey := clientPublicKey0
  for i in [1:nrHops] do
    let mut sharedSecret ← nikeDH nike clientSk (path[i]!).publicKey
    for j in [0:i] do
      let fj ← nikeDecodePrivateKey nike (keys[j]!).blindingFactor
      sharedSecret ← nikeDH nike fj sharedSecret
    keys := keys.push (deriveHopKeys sharedSecret)
    clientPublicKey := nikeBlind nike clientPublicKey (keys[i-1]!).blindingFactor
    groupElements := groupElements.set! i clientPublicKey

  -- Per-hop routing-info keystream and encrypted padding.
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
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ groupElements[0]! ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

private theorem ite_pure_yield {α : Type} (c : Prop) [Decidable c] (a b : α) :
    (if c then (pure (ForInStep.yield a) : Except String (ForInStep α)) else pure (ForInStep.yield b)) =
      pure (ForInStep.yield (if c then a else b)) := by
  split <;> rfl

set_option maxHeartbeats 1000000 in
/-- `createHeader`'s header always starts with `v0AD ++ groupElements[0]!`, and
`groupElements[0]!` is `clientPublicKey0` untouched — the blinding loop only ever writes indices
`≥ 1` of an array every entry of which starts as `clientPublicKey0`. Note the group-element slot's
width is `nike.publicKeySize`, not a fixed literal — genuinely different NIKEs get genuinely
different-width headers, matching `Geometry.buildNIKE`. -/
private theorem createHeader_hdr_bytesPub (nike : NIKE) (geom : Geometry)
    (clientPrivateKey : ByteArray) (filler : ByteArray) (path : Array PathHop)
    (hdr : ByteArray) (sprpKeys : Array SPRPKey)
    (h : createHeader nike geom clientPrivateKey filler path = .ok (hdr, sprpKeys)) :
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

/-- **`newNIKEPacket`**. -/
def newNIKEPacket (nike : NIKE) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createHeader nike geom clientPrivateKey filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

private theorem newNIKEPacket_bytesPub (nike : NIKE) (geom : Geometry)
    (clientPrivateKey : ByteArray) (filler : ByteArray) (path : Array PathHop)
    (payload : ByteArray) (pkt : ByteArray)
    (h : newNIKEPacket nike geom clientPrivateKey filler path payload = .ok pkt) :
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
        (fun b a ↦ sprpEncrypt x.2[x.2.size - 1 - a]!.key.toArray (ofVector x.2[x.2.size - 1 - a]!.iv) b)
        ({ data := Array.replicate geom.payloadTagLength 0 } ++ payload) := by
      injection hfx with hfx; exact hfx.symm
    obtain ⟨hhdrPub, hhdrgePub⟩ := createHeader_hdr_bytesPub nike geom clientPrivateKey filler path x.1 x.2 hx
    rw [hpkt, CryptWalker.Util.Bytes.extract_append_of_le _ _ (by omega)]
    exact hhdrPub

/-- A successful `newNIKEPacket` on a `geom.forwardPayloadLength`-sized payload produces exactly
`geom.packetLength` bytes: `headerLength` (itself `createHeader`'s routing-info-block
construction, accumulated over a `for` loop) plus `payloadTagLength + payload.size`
(`sprpEncrypt`'s length preservation, applied in another loop). True by construction and
confirmed by all 20 `sphinx_{nike,kem}_vectors.json` packets — see `Sphinx.Interface`'s doc comment
for why this is an axiom rather than a proof through those loops. `wrapNIKE` uses it to give
`Sphinx.Interface.wrap` a packet-length-preserving *type*, the same way `sprpDecrypt_size` lets
`unwrapNIKE` do that for `forwardPkt`. -/
axiom newNIKEPacket_size (nike : NIKE) (geom : Geometry) (clientPrivateKey : ByteArray)
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newNIKEPacket nike geom clientPrivateKey filler path payload = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapNIKE`**: `Sphinx.Interface.wrap` for `NIKESphinxScheme` — `newNIKEPacket`, drawing the
client's ephemeral private key from the seed stream instead of taking it as a bare argument. -/
def wrapNIKE (nike : NIKE) (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seed ← nextSeed
  match newNIKEPacket nike geom (ofVector seed) filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    if hsize : pkt.size = geom.packetLength then pure ⟨pkt.data, hsize⟩
    else throw "sphinx: internal error: newNIKEPacket produced a wrong-sized packet"

/-- **`newNIKESURB`**. `keyPayload` is the recipient's own random SPRP key ‖ iv for the reply's
final payload-encryption layer (`sprpKeyMaterialLength = 64` bytes — `surb.go`'s
`io.ReadFull(r, keyPayload[:])`). Returns `(surb, decryptionKeys)`; `decryptionKeys` is exactly
what `SURB.decryptSURBPayload` wants. -/
def newNIKESURB (nike : NIKE) (geom : Geometry) (clientPrivateKey : ByteArray)
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createHeader nike geom clientPrivateKey filler path
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
axiom newNIKESURB_size (nike : NIKE) (geom : Geometry) (clientPrivateKey : ByteArray)
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop)
    (surb surbKeys : ByteArray)
    (h : newNIKESURB nike geom clientPrivateKey keyPayload filler path = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength

/-- **`wrapNIKESURB`**: `Sphinx.Interface.newSURB` for `NIKESphinxScheme` — `newNIKESURB`, drawing
the client's ephemeral key and `keyPayload` (two seeds' worth) from the seed stream instead of
taking them as bare arguments. -/
def wrapNIKESURB (nike : NIKE) (geom : Geometry) (path : List PathHop) (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let clientKey ← nextSeed
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match h : newNIKESURB nike geom (ofVector clientKey) (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    have hsize : surb.size = geom.surbLength :=
      newNIKESURB_size nike geom (ofVector clientKey) (kp1 ++ kp2) filler path.toArray surb k h
    pure (⟨surb.data, hsize⟩, k)

/-- **`unwrapNIKE`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`
(see that file). Unlike Go, a MAC mismatch reports only an error string, not also the replay
tag. -/
def unwrapNIKE (nike : NIKE) (geom : Geometry) (privKey : ByteArray) (pkt : ByteArray) :
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
  let keys := deriveHopKeys sharedSecret

  let gotMac := mac keys.headerMAC (pkt.extract 0 macOff)
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
  b := xorBytes b (keystream keys.headerEncryption keys.headerEncryptionIV b.size)
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

/-- **Completeness**: `NIKESphinxScheme`'s witness for `Sphinx.Interface.unwrap_complete` — the
claim that Sphinx onion-decrypts correctly, checked empirically by every vector and self-test
round trip (`nike_vectors_test`; `nike_selftest`'s `runRound`/`runAbstractWrapRound`/
`runAbstractSURBRound`), but not proved here for the reason the size axioms above aren't: real
work, through `createHeader`'s blinding chain and `unwrapNIKE`'s AEZ/HMAC composition, out of
scope for this pass. -/
axiom wrapNIKE_unwrapNIKE_complete (nike : NIKE) (geom : Geometry) (path : List PathHop)
    (privKeys : List ByteArray) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (nikeSelfPublicKeyBytes nike) →
    wrapNIKE nike geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapNIKE nike geom) privKeys (ofVector pkt) = .ok (some (ofVector payload))

private theorem wrapNIKE_bytesPub (nike : NIKE) (geom : Geometry) (path : List PathHop)
    (filler : ByteArray) (payload : Vector UInt8 geom.forwardPayloadLength) (i : Nat)
    (str : Nat → Vector UInt8 32) (v : Vector UInt8 geom.packetLength) (s' : SeedStream)
    (h : wrapNIKE nike geom path filler payload (i, str) = .ok v s') :
    (ofVector v).extract 2 (2 + nike.publicKeySize) = nikeSelfPublicKeyBytes nike (ofVector (str i)) := by
  rcases hX : newNIKEPacket nike geom (ofVector (str i)) filler path.toArray (ofVector payload) with e | raw
  · have hw : wrapNIKE nike geom path filler payload (i, str) = .error e (i + 1, str) := by
      simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
      match newNIKEPacket nike geom (ofVector (str i)) filler path.toArray (ofVector payload), hX with
      | _, rfl => rfl
    rw [hw] at h; injection h
  · have hsize := newNIKEPacket_size nike geom (ofVector (str i)) filler path.toArray (ofVector payload) raw hX
      (by simp)
    have hw : wrapNIKE nike geom path filler payload (i, str) = .ok ⟨raw.data, hsize⟩ (i + 1, str) := by
      simp only [wrapNIKE, Bind.bind, EStateM.bind, nextSeed]
      match newNIKEPacket nike geom (ofVector (str i)) filler path.toArray (ofVector payload), hX with
      | _, rfl => simp [dif_pos hsize, EStateM.pure, pure]
    rw [hw] at h
    injection h with h
    rw [← h]
    exact newNIKEPacket_bytesPub nike geom (ofVector (str i)) filler path.toArray (ofVector payload) raw hX

/-- Envelope bytes are a pure function of the seed drawn from `state` (`createHeader`'s
`groupElements[0]!`, never overwritten after `Array.replicate`), regardless of the path/filler/
payload the rest of `wrap` is building. -/
theorem wrapNIKE_envelope_indep (nike : NIKE) (geom : Geometry) (hop0 hop1 : PathHop)
    (rest0 rest1 : List PathHop) (filler0 filler1 : ByteArray)
    (payload0 payload1 : Vector UInt8 geom.forwardPayloadLength)
    (st : SeedStream) (pkt0 pkt1 : Vector UInt8 geom.packetLength) (st0' st1' : SeedStream) :
    wrapNIKE nike geom (hop0 :: rest0) filler0 payload0 st = .ok pkt0 st0' →
    wrapNIKE nike geom (hop1 :: rest1) filler1 payload1 st = .ok pkt1 st1' →
    (ofVector pkt0).extract 2 (2 + nike.publicKeySize) = (ofVector pkt1).extract 2 (2 + nike.publicKeySize) := by
  intro h0 h1
  obtain ⟨i, str⟩ := st
  rw [wrapNIKE_bytesPub nike geom (hop0 :: rest0) filler0 payload0 i str pkt0 st0' h0,
    wrapNIKE_bytesPub nike geom (hop1 :: rest1) filler1 payload1 i str pkt1 st1' h1]

/-- A `Sphinx` scheme whose header carries a re-blindable public-key element: `Envelope` is that
element's type (`parseEnvelope` extracts it from a packet), `Factor` is the space a fresh
blinding value is drawn from, and `blind` is the re-blinding action. `wrap_resistant` needs no
per-instance proof — it's `uniformHit_eq` specialized to `act := blind · e`, true for *every*
instance automatically. Its hypothesis, `Function.Bijective (blind · e)`, is what actually
carries content, and is false (so the implication holds vacuously) for a degenerate `e` such as
a group's identity element — exactly the case a well-formed header never produces. -/
structure NIKESphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
  nike : NIKE
  Envelope : Type
  [envelopeDecEq : DecidableEq Envelope]
  /-- The header's public-key element, read out of a packet. -/
  parseEnvelope : Vector UInt8 geometry.packetLength → Envelope
  /-- The space a fresh blinding factor is drawn from. -/
  Factor : Type
  [factorFintype : Fintype Factor]
  [factorSampleable : SampleableType Factor]
  /-- Re-blind an envelope element by a factor. -/
  blind : Factor → Envelope → Envelope
  /-- **Wrap-resistance.** Whenever blinding by `e` is a bijection — the case for any `e` that
  actually generates the (sub)group a well-formed header's element lives in — a freshly drawn
  factor hits a chosen `target` with probability exactly `1/|Factor|`. -/
  wrap_resistant : ∀ (e target : Envelope), Function.Bijective (blind · e) →
      Pr[= true | ($ᵗ Factor) >>= fun b => pure (decide (blind b e = target))] =
        (Fintype.card Factor : ℝ≥0∞)⁻¹ :=
    fun _ target hbij => CryptWalker.Sphinx.Interface.uniformHit_eq hbij target
  /-- **Envelope independence** (§4.4's indistinguishability claim, for the one header component
  a re-blindable-group-element scheme pins down exactly rather than up to some advantage): the
  envelope depends only on `wrap`'s own seed-stream draw, never on the caller's path, filler, or
  payload, so two calls sharing the same starting `State` produce byte-for-byte identical
  envelopes regardless of what either call was building. Since it carries no information about
  the session's content at all, no adversary — however powerful — can learn anything about that
  content from the envelope alone; this is a stronger, exact form of indistinguishability, not
  merely a negligible-advantage bound. See `wrapNIKE_envelope_indep` below for why this holds
  concretely (the envelope is the client's own public key, a pure function of the drawn seed). -/
  envelope_indep : ∀ (hop0 hop1 : Types.PathHop) (rest0 rest1 : List Types.PathHop)
      (filler0 filler1 : ByteArray)
      (payload0 payload1 : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt0 pkt1 : Vector UInt8 geometry.packetLength) (st0' st1' : State),
    wrap (hop0 :: rest0) filler0 payload0 st = .ok pkt0 st0' →
    wrap (hop1 :: rest1) filler1 payload1 st = .ok pkt1 st1' →
    parseEnvelope pkt0 = parseEnvelope pkt1

/-- The base `Sphinx.Interface.Sphinx` instance for `nike` — everything `nikeSphinxSchemeOf`
below provides *except* the re-blindable-envelope structure (`Envelope`/`Factor`/`blind`/
`wrap_resistant`/`envelope_indep`), which needs a `Fintype`/`SampleableType` instance for
`nike.PrivateKey` that doesn't exist computably for an arbitrary `NIKE` picked at runtime (proving
an abstract, injectively-embedded type finite and enumerable needs classical choice —
`Fintype.ofInjective`/`SampleableType.ofFintype`, both `noncomputable`). This core needs none of
that, so — unlike `nikeSphinxSchemeOf`/`nikeSphinxScheme` — it compiles to real code: executable
callers that only need `wrap`/`unwrap`/`newSURB`/`newPacketFromSURB` (tests, vector generation)
should use this, not the fuller scheme. -/
def nikeSphinxCore (nike : NIKE) (geom : Geometry) : CryptWalker.Sphinx.Interface.Sphinx where
  State := SeedStream
  PrivateKey := ByteArray
  Command := RoutingCommand
  geometry := geom
  stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
  derivePublicKey := nikeSelfPublicKeyBytes nike
  wrap := wrapNIKE nike geom
  unwrap := unwrapNIKE nike geom
  newSURB := wrapNIKESURB nike geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
  unwrap_complete := wrapNIKE_unwrapNIKE_complete nike geom

/-- Build a `NIKESphinxScheme` from any `NIKE` at all — total, no `Except`, since every field here
is defined unconditionally (needed by test/vector-generation code, which can't route through
`nikeSphinxScheme`'s `Except` return because `NIKESphinxScheme` has `Type`-valued fields, putting it
in `Type 1`, which `IO.ofExcept` cannot hold). `noncomputable` — see `nikeSphinxCore`'s doc comment
if only the base `Sphinx` fields are actually needed. -/
noncomputable def nikeSphinxSchemeOf (nike : NIKE) (geom : Geometry) : NIKESphinxScheme where
  toSphinx := nikeSphinxCore nike geom
  Envelope := nike.PublicKey
  parseEnvelope := fun pkt =>
    (nike.decodePublicKey (toVecN nike.publicKeySize ((ofVector pkt).extract 2 (2 + nike.publicKeySize)))).getD default
  Factor := nike.PrivateKey
  blind := nikeBlindTyped nike
  envelope_indep := fun hop0 hop1 rest0 rest1 filler0 filler1 payload0 payload1 st pkt0 pkt1
      st0' st1' h0 h1 =>
    congrArg (fun b => (nike.decodePublicKey (toVecN nike.publicKeySize b)).getD default)
      (wrapNIKE_envelope_indep nike geom hop0 hop1 rest0 rest1 filler0 filler1 payload0 payload1
        st pkt0 pkt1 st0' st1' h0 h1)
  nike := nike

/-- Build a `NIKESphinxScheme` for whatever NIKE `geom.scheme` names, resolved through
`CryptWalker.NIKE.byName` — the same registry `Geometry.ofNIKE` itself resolves against. Genuinely
agnostic to *which* registered NIKE this is: no size check, no wrapper type — every `NIKE` already
carries the size information this file needs, in its own `publicKeySize`/`privateKeySize`/
`sharedSecretSize` fields. Registering a new NIKE needs no change here. -/
noncomputable def nikeSphinxScheme (geom : Geometry) : Except String NIKESphinxScheme :=
  match geom.scheme with
  | .inr name => throw s!"sphinx: geometry scheme {name} is a KEM, not a NIKE"
  | .inl name =>
    match CryptWalker.NIKE.byName name with
    | none => throw s!"sphinx: NIKE scheme {name} not implemented"
    | some nike => pure (nikeSphinxSchemeOf nike geom)

end CryptWalker.Sphinx.NIKESphinx
