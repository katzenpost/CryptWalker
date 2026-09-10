/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.Sphinx
import CryptWalker.Sphinx.Common
import CryptWalker.Sphinx.NIKESphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.NIKE.X25519
import CryptWalker.KEM.Adapter
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
open CryptWalker.NIKE.X25519 (PublicKey PrivateKey curve25519 basepointBytes)
open CryptWalker.KEM.Adapter (encapM decapM initWith)
open CryptWalker.KEM (sha256v1PRF)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

/-! # KEM-Sphinx (X25519, via the NIKE→KEM adapter)

Port of `kemsphinx.go`, concrete to `KEM.kemX25519` (`sha256-v1` PRF over X25519). Differences
from `NIKESphinx`, per `kemsphinx.go`/`docs/specs/kemsphinx.md`:

* One KEM encapsulation per hop, independent of the others — no blinding chain, so no
  `HopKeys.blindingFactor` (reused from `NIKESphinx` regardless, unused, matching how Go reuses
  `crypto.PacketKeys` with `BlindingFactor = nil` rather than a separate type).
* The header's group-element field becomes a KEM ciphertext (32 bytes here); every non-terminal
  hop's per-hop routing-info block embeds the *next* hop's ciphertext in its last 32 bytes,
  rather than carrying it via a `NextNodeHop` command field.
* Forwarding just copies the embedded next-hop ciphertext into the group-element slot — no
  `Blind` step, since there is no group element to re-blind.

`ctSize` (32) is `kemX25519`'s `ciphertextSize` — hardcoded here the same way `NIKESphinx`
hardcodes X25519's 32-byte public key size, rather than threaded from `KEM.KEM`. -/

private def ctSize : Nat := 32

private def encap (pk : Vector UInt8 32) (seed : Vector UInt8 32) :
    Option (Vector UInt8 32 × Vector UInt8 32) :=
  match encapM sha256v1PRF CryptWalker.NIKE.X25519.LadderScheme (⟨pk⟩ : PublicKey) (initWith (fun _ => seed)) with
  | .ok (ct, ss) _ => some (ct.data, ss)
  | .error _ _ => none

private def decap (sk ct : Vector UInt8 32) : Option (Vector UInt8 32) :=
  match decapM sha256v1PRF CryptWalker.NIKE.X25519.LadderScheme (⟨sk⟩ : PrivateKey) (⟨ct⟩ : PublicKey)
      (initWith (fun _ => Vector.replicate 32 0)) with
  | .ok ss _ => some ss
  | .error _ _ => none

/-- **`createKEMHeader`**. `ephemeralSeeds` (one per hop) plays the role Go's `io.Reader` does
inside each `Encapsulate` call; `filler` is as in `NIKESphinx.createHeader`. -/
def createKEMHeader (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray)
    (path : Array PathHop) : Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if ephemeralSeeds.size ≠ nrHops then throw "sphinx: wrong number of ephemeral seeds"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  -- One independent encapsulation per hop.
  let mut kemElements : Array (Vector UInt8 32) := #[]
  let mut keys : Array HopKeys := #[]
  for i in [0:nrHops] do
    match encap (path[i]!).publicKey (ephemeralSeeds[i]!) with
    | none => throw "sphinx: KEM encapsulation failed"
    | some (ct, ss) =>
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
  -- next-hop ciphertext into the last ctSize bytes of its own fragment.
  let mut routingInfo : ByteArray := if geom.nrHops > nrHops then filler else ByteArray.empty
  let mut macBytes : ByteArray := ByteArray.empty
  for iRev in [0:nrHops] do
    let i := nrHops - 1 - iRev
    let isTerminal := i == nrHops - 1
    let hop := path[i]!
    let mut riFragment ← commandsToBytes geom hop.commands
    if !isTerminal then
      let next := path[i + 1]!
      riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
    riFragment := zeroPadTo geom.perHopRoutingInfoLength riFragment
    if !isTerminal then
      riFragment := riFragment.extract 0 (geom.perHopRoutingInfoLength - ctSize)
        ++ ofVector (kemElements[i + 1]!)
    routingInfo := riFragment ++ routingInfo
    routingInfo := xorBytes routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ ofVector (kemElements[i]!) ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ ofVector (kemElements[0]!) ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

/-- **`newKEMPacket`**. -/
def newKEMPacket (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createKEMHeader geom ephemeralSeeds filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- As `NIKESphinx.newNIKEPacket_size`. -/
axiom newKEMPacket_size (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newKEMPacket geom ephemeralSeeds filler path payload = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength

open CryptWalker.Sphinx.Sphinx (SeedStream nextSeed unwrapChainAux)

/-- **`wrapKEM`**: `Sphinx.Sphinx.wrap` for `KEMSphinxScheme` — `newKEMPacket`, drawing one
ephemeral seed per hop from the seed stream instead of taking them as a bare array. -/
def wrapKEM (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  match h : newKEMPacket geom seeds filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    have hsize : pkt.size = geom.packetLength :=
      newKEMPacket_size geom seeds filler path.toArray (ofVector payload) pkt h (by simp)
    pure ⟨pkt.data, hsize⟩

/-- **`newKEMSURB`**. As `NIKESphinx.newNIKESURB`, over `createKEMHeader`. -/
def newKEMSURB (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32)) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop) : Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createKEMHeader geom ephemeralSeeds filler path
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `NIKESphinx.newNIKESURB_size`. -/
axiom newKEMSURB_size (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32)) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop) (surb surbKeys : ByteArray)
    (h : newKEMSURB geom ephemeralSeeds keyPayload filler path = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength

/-- **`wrapKEMSURB`**: `Sphinx.Sphinx.newSURB` for `KEMSphinxScheme` — draws one ephemeral seed
per hop plus `keyPayload` (two seeds' worth) from the seed stream. -/
def wrapKEMSURB (geom : Geometry) (path : List PathHop) (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match h : newKEMSURB geom seeds (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    have hsize : surb.size = geom.surbLength :=
      newKEMSURB_size geom seeds (kp1 ++ kp2) filler path.toArray surb k h
    pure (⟨surb.data, hsize⟩, k)

/-- **`unwrapKEM`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Sphinx.unwrap`.
Forwarding copies the next-hop ciphertext straight out of the decrypted routing-info block —
unlike `unwrapNIKE`, no `Blind` step, since there is no group element to re-blind. -/
def unwrapKEM (geom : Geometry) (privKey : Vector UInt8 32) (pkt : ByteArray) :
    Except String
      (Option ByteArray × Vector UInt8 32 × List RoutingCommand × Option (Vector UInt8 pkt.size)) := do
  let geOff := 2
  let riOff := geOff + ctSize
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  if h1 : pkt.size < payloadOff then throw "sphinx: invalid packet, truncated"
  else do
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let kemCiphertext := toVec32 (pkt.extract geOff riOff)
  let replayTag := sha512_256 (ofVector kemCiphertext)
  match decap privKey kemCiphertext with
  | none => throw "sphinx: KEM decapsulation failed"
  | some sharedSecret =>

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

  let cmdBuf := b.extract 0 (geom.perHopRoutingInfoLength - ctSize)
  let nextCiphertext := toVec32 (b.extract (geom.perHopRoutingInfoLength - ctSize) geom.perHopRoutingInfoLength)
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
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    have hnewPayload : newPayload.size = pkt.size - payloadOff := by
      show (if decPayload.size > 0 then decPayload else rawPayload).size = pkt.size - payloadOff
      split
      · rw [hdec, hraw]
      · rw [hraw]
    let newPkt := v0AD ++ ofVector nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    have hnewPkt : newPkt.size = pkt.size := by
      show (v0AD ++ ofVector nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload).size
        = pkt.size
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          Util.Bytes.size_ofVector, Util.Bytes.size_ofVector, hnri, hnewPayload]
      have hv0 : v0AD.size = 2 := rfl
      have hmac : macLength = 32 := rfl
      have hctSize : ctSize = 32 := rfl
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
`Sphinx.Sphinx.unwrap_complete`. `derivePublicKey` is the same X25519 formula NIKE's is — a
`kemX25519` keypair *is* an X25519 keypair (see this file's module doc). -/
axiom wrapKEM_unwrapKEM_complete (geom : Geometry) (path : List PathHop)
    (privKeys : List (Vector UInt8 32)) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (fun sk => curve25519 sk basepointBytes) →
    wrapKEM geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapKEM geom) privKeys (ofVector pkt) = .ok (some (ofVector payload))

/-- KEM-Sphinx (X25519 via the NIKE→KEM adapter) as a `Sphinx.Sphinx` instance. -/
def KEMSphinxScheme (geom : Geometry) : CryptWalker.Sphinx.Sphinx.Sphinx where
  State := SeedStream
  PrivateKey := Vector UInt8 32
  Command := RoutingCommand
  packetLength := geom.packetLength
  payloadLength := geom.forwardPayloadLength
  surbLength := geom.surbLength
  stateI := ⟨CryptWalker.Sphinx.Sphinx.initWith (fun _ => Vector.replicate 32 0)⟩
  derivePublicKey := fun sk => curve25519 sk basepointBytes
  wrap := wrapKEM geom
  unwrap := unwrapKEM geom
  newSURB := wrapKEMSURB geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
  unwrap_complete := wrapKEM_unwrapKEM_complete geom

end CryptWalker.Sphinx.KEMSphinx
