/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.Crypto.KDF
import CryptWalker.Sphinx.Crypto.ChaCha20
import CryptWalker.Sphinx.Crypto.HMAC
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.NIKE.X25519
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.NikeSphinx

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Crypto.KDF (PacketKeys sphinxKDF)
open CryptWalker.Sphinx.Crypto.ChaCha20 (keystream32)
open CryptWalker.Sphinx.Crypto.HMAC (hmacSha256)
open CryptWalker.Sphinx.Crypto.Stream (keystream)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.NIKE.X25519 (curve25519 basepointBytes)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

/-! # NIKE-Sphinx (X25519)

Port of `sphinx.go`'s NIKE path (`createHeader`, `newNikePacket`, `unwrapNike`), concrete to
X25519 rather than an abstract NIKE — this pass's scope. Randomness `createHeader` needs (the
client's ephemeral private key, and the hop-count-hiding filler when the path is shorter than
`geom.nrHops`) is threaded in explicitly rather than drawn from an `IO`/IO.Reader, so the
function is pure and testable; see `Sphinx.API` for an `IO`-based convenience wrapper.

`unwrapNike`, unlike `createHeader`, needs no randomness — it is what `Sphinx.Crypto`'s
cross-implementation vectors ultimately validate: katzenpost's own `sphinx_vectors.json` records
Sphinx packets built with a client ephemeral key that isn't itself recorded (so `createHeader`'s
*exact* output bytes can't be independently reproduced), but `Unwrap` is deterministic and *is*
checked, hop by hop, against the recorded `Packets[i+1]`. -/

private def v0AD : ByteArray := ⟨#[0, 0]⟩

private def toVec32 (a : ByteArray) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => a.get! i.val

/-- Diffie-Hellman: `curve25519(sk, pk)`. Also used, with a "shared secret treated as a public
key" or "blinding factor as the scalar" reading, for the blinding-chain and per-hop
`groupElement`/`clientPublicKey` re-blinding steps below — `hpqc/nike/x25519`'s `Blind` *is*
literally `Exp`/`curve25519`, just argument-relabeled. -/
private def dh (sk pk : Vector UInt8 32) : Vector UInt8 32 := curve25519 sk pk

/-- `nike.Blind(pk, factor)` = `Exp(pk, factor)` = `curve25519(factor, pk)` — the scalar and
point arguments swapped relative to `dh`'s usual "my private key, their public key" reading. -/
private def blind (pk factor : Vector UInt8 32) : Vector UInt8 32 := curve25519 factor pk

/-- The NIKE private key `internal/crypto.KDF`'s `BlindingFactor` derives from a `PacketKeys`'s
seed: `rand.NewDeterministicRandReader(seed)`'s first 32 bytes, read raw (unclamped — RFC 7748
clamping happens inside `curve25519`, not at key-generation time, matching
`nike/x25519.NewKeypair`). -/
private def blindingFactorPrivKey (seed : Vector UInt8 32) : Vector UInt8 32 :=
  toVec32 ⟨keystream32 seed.toArray⟩

private def xor (a b : ByteArray) : ByteArray := ⟨a.data.mapIdx fun i x => x ^^^ b.data.getD i 0⟩

private def mac (key : Vector UInt8 32) (msg : ByteArray) : Vector UInt8 32 :=
  hmacSha256 (ofVector key) msg

/-- Everything `crypto.KDF` derives for one hop, with the raw `BlindingFactor` seed already
turned into the NIKE private key it represents (`internal/crypto.PacketKeys.BlindingFactor` is
itself a `nike.PrivateKey`, not a raw seed — `deriveHopKeys` is the point where that conversion
happens, once, rather than at every later use site). -/
structure HopKeys where
  headerMAC : Vector UInt8 32
  headerEncryption : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption : Vector UInt8 48
  blindingFactor : Vector UInt8 32
  deriving Inhabited

def deriveHopKeys (sharedSecret : Vector UInt8 32) : HopKeys :=
  let pk : PacketKeys := sphinxKDF (ofVector sharedSecret)
  { headerMAC := pk.headerMAC
    headerEncryption := pk.headerEncryption
    headerEncryptionIV := pk.headerEncryptionIV
    payloadEncryption := pk.payloadEncryption
    blindingFactor := blindingFactorPrivKey pk.blindingFactorSeed }

/-- `commandsToBytes`, simplified: drops the "commands must not include a bare `NextNodeHop`"
and "must leave spare room for one" caller-discipline checks from the Go original — nothing
here is ever called with attacker-controlled commands. The oversize check is kept, since
violating it would silently truncate/corrupt the header rather than merely reject bad input. -/
def commandsToBytes (geom : Geometry) (cmds : List RoutingCommand) : Except String ByteArray := do
  let b := cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
  if b.size > geom.perHopRoutingInfoLength then
    throw "sphinx: invalid commands, oversized serialized block"
  pure b

private def zeroPadTo (n : Nat) (b : ByteArray) : ByteArray :=
  if b.size ≥ n then b else b ++ ⟨Array.replicate (n - b.size) 0⟩

/-- **`createHeader`**. `filler` must be exactly `(geom.nrHops - path.size) *
geom.perHopRoutingInfoLength` bytes (ignored, and may be empty, when `path.size = geom.nrHops`)
— the random padding that hides a shorter-than-maximum path's true hop count. -/
def createHeader (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (filler : ByteArray)
    (path : Array PathHop) : Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  let clientPublicKey0 := dh clientPrivateKey basepointBytes

  -- Per-hop shared secrets/keys, and the (progressively blinded) group elements.
  let mut groupElements : Array (Vector UInt8 32) := Array.replicate nrHops clientPublicKey0
  let mut keys : Array HopKeys := #[deriveHopKeys (dh clientPrivateKey (path[0]!).nikePublicKey)]
  let mut clientPublicKey := clientPublicKey0
  for i in [1:nrHops] do
    let mut sharedSecret := dh clientPrivateKey (path[i]!).nikePublicKey
    for j in [0:i] do
      sharedSecret := dh (keys[j]!).blindingFactor sharedSecret
    keys := keys.push (deriveHopKeys sharedSecret)
    clientPublicKey := blind clientPublicKey (keys[i-1]!).blindingFactor
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
      thisPad := xor (thisPad.extract 0 prevPad.size) prevPad
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
    let mut riFragment ← commandsToBytes geom hop.commands
    if !isTerminal then
      let next := path[i + 1]!
      riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
    routingInfo := zeroPadTo geom.perHopRoutingInfoLength riFragment ++ routingInfo
    routingInfo := xor routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ ofVector (groupElements[i]!) ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ ofVector (groupElements[0]!) ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

/-- **`newNikePacket`**. -/
def newNikePacket (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createHeader geom clientPrivateKey filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- The result of one hop's `Unwrap`: either a terminal `payload` (`none` when forwarding), the
replay tag, the parsed commands, and — when there is a next hop — the packet to forward. -/
structure UnwrapResult where
  payload : Option ByteArray
  replayTag : Vector UInt8 32
  cmds : List RoutingCommand
  forwardPkt : Option ByteArray

/-- **`unwrapNike`**. Unlike Go, a MAC mismatch reports only an error string, not also the
replay tag (`Except` has no side channel for it) — this pass has no caller that needs a tag
alongside a rejection. -/
def unwrapNike (geom : Geometry) (privKey : Vector UInt8 32) (pkt : ByteArray) :
    Except String UnwrapResult := do
  let geOff := 2
  let riOff := geOff + 32
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  if pkt.size < geom.headerLength then throw "sphinx: invalid packet, truncated"
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let groupElement := toVec32 (pkt.extract geOff riOff)
  let sharedSecret := dh privKey groupElement
  let replayTag := sha512_256 (ofVector groupElement)
  let keys := deriveHopKeys sharedSecret

  let gotMac := mac keys.headerMAC (pkt.extract 0 macOff)
  if (ofVector gotMac).data ≠ (pkt.extract macOff (macOff + macLength)).data then
    throw "sphinx: invalid packet, MAC mismatch"

  -- Decrypt the (padding-extended) routing_info block and split off this hop's fragment.
  let mut b : ByteArray := pkt.extract riOff macOff ++ ⟨Array.replicate geom.perHopRoutingInfoLength 0⟩
  b := xor b (keystream keys.headerEncryption keys.headerEncryptionIV b.size)
  let cmdBuf := b.extract 0 geom.perHopRoutingInfoLength
  let newRoutingInfo := b.extract geom.perHopRoutingInfoLength b.size

  let cmds ← parseAll cmdBuf
  let nextNode := cmds.findSome? fun
    | .nextNodeHop id m => some (id, m)
    | _ => none
  let hasSurbReply := cmds.any fun
    | .surbReply _ => true
    | _ => false

  let rawPayload := pkt.extract payloadOff pkt.size
  let decPayload :=
    if rawPayload.size > 0 then sprpDecrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
    else rawPayload

  match nextNode with
  | some (_nextID, nextMAC) =>
    let newGroupElement := blind groupElement keys.blindingFactor
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    let newPkt := v0AD ++ ofVector newGroupElement ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    pure { payload := none, replayTag, cmds, forwardPkt := some newPkt }
  | none =>
    if decPayload.size < geom.payloadTagLength then throw "sphinx: truncated payload"
    if hasSurbReply then
      pure { payload := some decPayload, replayTag, cmds, forwardPkt := none }
    else
      let tag := decPayload.extract 0 geom.payloadTagLength
      if !tag.data.all (· == 0) then throw "sphinx: payload auth failed"
      pure { payload := some (decPayload.extract geom.payloadTagLength decPayload.size),
             replayTag, cmds, forwardPkt := none }

end CryptWalker.Sphinx.NikeSphinx
