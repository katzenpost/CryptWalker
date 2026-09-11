/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants

namespace CryptWalker.Sphinx.Geometry

open CryptWalker.Sphinx.Constants

/-! # Sphinx packet geometry

Port of `katzenpost/core/sphinx/geo/geo.go` + `geo_impl.go`'s `geometryFactory`: given a hop
count, a target payload size, and the chosen scheme's per-element size (a NIKE public key, or a
KEM ciphertext — the two are mutually exclusive in Go's `Geometry`, modeled here as which
constructor is called rather than a nullable pair of fields), compute every fixed byte offset
Sphinx's header/routing-info/packet layout needs.

Dropped relative to Go's `Geometry`: `NIKEName`/`KEMName` (scheme lookup by name — this Lean
port fixes the scheme at the type level instead) and `Validate`/`Marshal`/`Display`/`Hash`/
`String` (I/O-and-serialization conveniences, orthogonal to the packet crypto this project is
porting). -/

structure Geometry where
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

/-- `GeometryFromUserForwardPayloadLength`, parametrized by a NIKE scheme's public-key size
(`nike.PublicKeySize()`) instead of a scheme lookup. -/
def ofNIKE (nikePublicKeySize userForwardPayloadLength : Nat) (withSURB : Bool) (nrHops : Nat) :
    Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength
  let routingInfo := perHop * nrHops
  let header := adLength + nikePublicKeySize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { packetLength := header + payloadTagLength + forwardPayload
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

/-- `KEMGeometryFromUserForwardPayloadLength`, parametrized by a KEM scheme's ciphertext size
(`kem.CiphertextSize()`). -/
def ofKEM (kemCiphertextSize userForwardPayloadLength : Nat) (withSURB : Bool) (nrHops : Nat) :
    Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength + kemCiphertextSize
  let routingInfo := perHop * nrHops
  let header := adLength + kemCiphertextSize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { packetLength := header + payloadTagLength + forwardPayload
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

end CryptWalker.Sphinx.Geometry
