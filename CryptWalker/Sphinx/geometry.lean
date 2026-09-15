/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Geometry

-- `Geometry` repeats the namespace, as `NIKE`/`KEM`/`Sphinx` do theirs; harmless (see
-- `sphinx.lean`'s own suppression of this same linter).
set_option linter.dupNamespace false

open CryptWalker.Sphinx.Constants

/-! # Sphinx packet geometry

Port of `katzenpost/core/sphinx/geo/geo.go` + `geo_impl.go`'s `geometryFactory`: given a hop
count, a target payload size, and the chosen scheme, compute every fixed byte offset Sphinx's
header/routing-info/packet layout needs.

`ofNIKE`/`ofKEM` take a bare scheme name (as Go's config format does) and resolve it against
`CryptWalker.NIKE.byName`/`CryptWalker.KEM.byName`, so a returned `Geometry`'s stored name and
derived sizes can never disagree. `Geometry.scheme : String ⊕ String` (`Sum.inl`/`Sum.inr`)
replaces Go's separate nullable `NIKEName`/`KEMName`, making "exactly one of NIKE or KEM" a fact
of the type rather than a runtime invariant.

Dropped relative to Go's `Geometry`: `Marshal`/`Display`/`Hash`/`String` (I/O-and-display
conveniences, orthogonal to the packet crypto this project is porting). -/

structure Geometry where
  /-- Which scheme this geometry's sizes were derived for, by its canonical `hpqc` name —
  `Sum.inl` for a NIKE, `Sum.inr` for a KEM. Replaces Go's `NIKEName`/`KEMName` pair. -/
  scheme                       : String ⊕ String
  packetLength                : Nat
  nrHops                      : Nat
  headerLength                 : Nat
  routingInfoLength            : Nat
  perHopRoutingInfoLength      : Nat
  surbLength                   : Nat
  sphinxPlaintextHeaderLength  : Nat
  payloadTagLength             : Nat
  forwardPayloadLength         : Nat
  userForwardPayloadLength     : Nat
  nextNodeHopLength            : Nat
  sprpKeyMaterialLength        : Nat
  deriving Repr

/-- `geometryFactory.deriveForwardPayloadLength`: the payload size a SURB-carrying packet needs,
given the size the caller actually wants delivered. -/
private def deriveForwardPayloadLength (surbLen userForwardPayloadLength : Nat) : Nat :=
  userForwardPayloadLength + sphinxPlaintextHeaderLength + surbLen

private def buildNIKE (name : String) (nikePublicKeySize userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) : Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength
  let routingInfo := perHop * nrHops
  let header := adLength + nikePublicKeySize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { scheme := .inl name
    packetLength := header + payloadTagLength + forwardPayload
    nrHops
    headerLength := header
    routingInfoLength := routingInfo
    perHopRoutingInfoLength := perHop
    surbLength := surb
    sphinxPlaintextHeaderLength := sphinxPlaintextHeaderLength
    payloadTagLength := payloadTagLength
    forwardPayloadLength := forwardPayload
    userForwardPayloadLength := userForwardPayloadLength
    nextNodeHopLength := nextNodeHopLength
    sprpKeyMaterialLength := sprpKeyMaterialLength }

private def buildKEM (name : String) (kemCiphertextSize userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) : Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength + kemCiphertextSize
  let routingInfo := perHop * nrHops
  let header := adLength + kemCiphertextSize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { scheme := .inr name
    packetLength := header + payloadTagLength + forwardPayload
    nrHops
    headerLength := header
    routingInfoLength := routingInfo
    perHopRoutingInfoLength := perHop
    surbLength := surb
    sphinxPlaintextHeaderLength := sphinxPlaintextHeaderLength
    payloadTagLength := payloadTagLength
    forwardPayloadLength := forwardPayload
    userForwardPayloadLength := userForwardPayloadLength
    nextNodeHopLength := nextNodeHopLength
    sprpKeyMaterialLength := sprpKeyMaterialLength }

/-- `GeometryFromUserForwardPayloadLength`, ported with `Validate`'s scheme-name check folded in:
`nikeSchemeName` resolves against `CryptWalker.NIKE.byName`, and the public-key size comes only
from that lookup, never from a caller-supplied number. -/
def ofNIKE (nikeSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.NIKE.byName nikeSchemeName with
  | none => throw s!"geometry has invalid NIKE Scheme {nikeSchemeName}"
  | some scheme =>
    pure (buildNIKE nikeSchemeName scheme.publicKeySize userForwardPayloadLength withSURB nrHops)

/-- `KEMGeometryFromUserForwardPayloadLength`, ported the same way — see `ofNIKE`. -/
def ofKEM (kemSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.KEM.byName kemSchemeName with
  | none => throw s!"geometry has invalid KEM Scheme {kemSchemeName}"
  | some scheme =>
    pure (buildKEM kemSchemeName scheme.ciphertextSize userForwardPayloadLength withSURB nrHops)

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)

/-- What it means for `geom` to have actually been built for `nike` via `buildNIKE`: `buildNIKE`'s
field equations, spelled out directly. Every `ofNIKE` result satisfies this for the `nike` it
resolved (`ofNIKE_validForNIKE`). Needed because `createHeader`/`newNIKEPacket`/`newNIKESURB`
accept any `(nike, geom)` pair — nothing in their types pins the two together. -/
@[reducible] def Geometry.ValidForNIKE (geom : Geometry) (nike : NIKE) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + nike.publicKeySize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- As `Geometry.ValidForNIKE`, for the KEM side (`buildKEM`): the ciphertext slot's width is
`kem.ciphertextSize`, folded into `perHopRoutingInfoLength` too, since `createKEMHeader` embeds a
full ciphertext at every hop, not just the header's leading element. -/
@[reducible] def Geometry.ValidForKEM (geom : Geometry) (kem : KEM) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength + kem.ciphertextSize ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + kem.ciphertextSize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

theorem ofNIKE_validForNIKE (nikeSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry) (nike : NIKE)
    (h : ofNIKE nikeSchemeName userForwardPayloadLength withSURB nrHops = .ok geom)
    (hn : CryptWalker.NIKE.byName nikeSchemeName = some nike) :
    geom.ValidForNIKE nike := by
  unfold ofNIKE at h
  rw [hn] at h
  injection h with h
  subst h
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem ofKEM_validForKEM (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry) (kem : KEM)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom)
    (hk : CryptWalker.KEM.byName kemSchemeName = some kem) :
    geom.ValidForKEM kem := by
  unfold ofKEM at h
  rw [hk] at h
  injection h with h
  subst h
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- `payloadTagLength` (`Constants.payloadTagLength`) is a pure protocol constant — `buildKEM`
sets it the same way regardless of which `kem` resolved, so unlike `ValidForKEM` this needs no
`byName` witness. Lets a caller holding only `ofKEM`'s success proof discharge
`wrapKEM_unwrapKEM_complete_valid`'s `h16` hypothesis. -/
theorem ofKEM_payloadTagLength (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofKEM at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

/-- As `ofKEM_payloadTagLength`, for the NIKE side. -/
theorem ofNIKE_payloadTagLength (nikeSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofNIKE nikeSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofNIKE at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

end CryptWalker.Sphinx.Geometry
