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

A CBOR map keyed by the katzenpost field names. Messages carry the fields in declaration order;
`hash` is taken over the canonical encoding, whose keys are sorted shortest first and then
bytewise. -/

/-- Each field's key and encoding, in declaration order. -/
def Geometry.fields (g : Geometry) : List (String × Encoding) :=
  [("PacketLength", encode g.packetLength),
   ("NrHops", encode g.nrHops),
   ("HeaderLength", encode g.headerLength),
   ("RoutingInfoLength", encode g.routingInfoLength),
   ("PerHopRoutingInfoLength", encode g.perHopRoutingInfoLength),
   ("SURBLength", encode g.surbLength),
   ("SphinxPlaintextHeaderLength", encode g.sphinxPlaintextHeaderLength),
   ("PayloadTagLength", encode g.payloadTagLength),
   ("ForwardPayloadLength", encode g.forwardPayloadLength),
   ("UserForwardPayloadLength", encode g.userForwardPayloadLength),
   ("NextNodeHopLength", encode g.nextNodeHopLength),
   ("SPRPKeyMaterialLength", encode g.sprpKeyMaterialLength),
   ("NIKEName", encode g.nikeName),
   ("KEMName", encode g.kemName)]

def Geometry.keys : List String := (default : Geometry).fields.map (·.1)

/-- Missing keys decode to zero or the empty string; unknown keys are rejected. -/
instance : Serialise Geometry where
  encode g := encodeRecord (g.fields.map fun (k, e) => (k, some e))
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

/-- Shorter keys first, then bytewise. -/
private def canonicalLt (a b : String) : Bool :=
  a.utf8ByteSize < b.utf8ByteSize ||
    (a.utf8ByteSize == b.utf8ByteSize && decide (a.toUTF8.toList < b.toUTF8.toList))

/-- The encoding with keys in canonical order. -/
def Geometry.canonical (g : Geometry) : ByteArray :=
  toByteArray (encodeRecord ((g.fields.mergeSort fun a b => canonicalLt a.1 b.1).map
    fun (k, e) => (k, some e)))

/-- BLAKE2b-256 of the canonical encoding; the PKI document's `SphinxGeometryHash`. -/
def Geometry.hash (g : Geometry) : Vector UInt8 32 :=
  CryptWalker.Hash.Blake2b.hash256 g.canonical

end CryptWalker.Sphinx.Geometry
