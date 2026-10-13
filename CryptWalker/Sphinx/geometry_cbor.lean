/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg
import CryptWalker.Sphinx.geometry
import CryptWalker.Hash.Blake2b

namespace CryptWalker.Sphinx.Geometry

set_option linter.dupNamespace false

open Cborg

/-! # Geometry CBOR encoding and hash

A CBOR map keyed by the katzenpost field names. Keys are written in canonical order (shorter
first, then bytewise), so the encoding is the canonical one that `hash` is taken over. -/

def Geometry.keys : List String :=
  ["NrHops", "KEMName", "NIKEName", "SURBLength", "HeaderLength", "PacketLength",
   "PayloadTagLength", "NextNodeHopLength", "RoutingInfoLength", "ForwardPayloadLength",
   "SPRPKeyMaterialLength", "PerHopRoutingInfoLength", "UserForwardPayloadLength",
   "SphinxPlaintextHeaderLength"]

/-- Missing keys decode to zero or the empty string; unknown keys are rejected. -/
instance : Serialise Geometry where
  encode g := encodeRecord [
    field "NrHops" g.nrHops,
    field "KEMName" g.kemName,
    field "NIKEName" g.nikeName,
    field "SURBLength" g.surbLength,
    field "HeaderLength" g.headerLength,
    field "PacketLength" g.packetLength,
    field "PayloadTagLength" g.payloadTagLength,
    field "NextNodeHopLength" g.nextNodeHopLength,
    field "RoutingInfoLength" g.routingInfoLength,
    field "ForwardPayloadLength" g.forwardPayloadLength,
    field "SPRPKeyMaterialLength" g.sprpKeyMaterialLength,
    field "PerHopRoutingInfoLength" g.perHopRoutingInfoLength,
    field "UserForwardPayloadLength" g.userForwardPayloadLength,
    field "SphinxPlaintextHeaderLength" g.sphinxPlaintextHeaderLength]
  decode := do
    let r ← decodeRecord
    r.onlyKeys Geometry.keys
    return {
      packetLength := ← r.withDefault "PacketLength" 0
      nrHops := ← r.withDefault "NrHops" 0
      headerLength := ← r.withDefault "HeaderLength" 0
      routingInfoLength := ← r.withDefault "RoutingInfoLength" 0
      perHopRoutingInfoLength := ← r.withDefault "PerHopRoutingInfoLength" 0
      surbLength := ← r.withDefault "SURBLength" 0
      sphinxPlaintextHeaderLength := ← r.withDefault "SphinxPlaintextHeaderLength" 0
      payloadTagLength := ← r.withDefault "PayloadTagLength" 0
      forwardPayloadLength := ← r.withDefault "ForwardPayloadLength" 0
      userForwardPayloadLength := ← r.withDefault "UserForwardPayloadLength" 0
      nextNodeHopLength := ← r.withDefault "NextNodeHopLength" 0
      sprpKeyMaterialLength := ← r.withDefault "SPRPKeyMaterialLength" 0
      nikeName := ← r.withDefault "NIKEName" ""
      kemName := ← r.withDefault "KEMName" "" }

/-- BLAKE2b-256 of the canonical encoding; the PKI document's `SphinxGeometryHash`. -/
def Geometry.hash (g : Geometry) : Vector UInt8 32 :=
  CryptWalker.Hash.Blake2b.hash256 (serialise g)

end CryptWalker.Sphinx.Geometry
