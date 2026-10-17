/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.Sphinx.constants
import Cryptlib.Protocols.Sphinx.geometry
import Cryptlib.Protocols.Sphinx.commands
import Cryptlib.Protocols.Sphinx.types
import Cryptlib.Protocols.Sphinx.sphinx
import Cryptlib.Protocols.Sphinx.common
import Cryptlib.Protocols.Sphinx.surb
import Cryptlib.Protocols.Sphinx.kdf
import Cryptlib.Primitives.Cipher.ChaCha20
import Cryptlib.Primitives.WideBlockCipher.WideBlockCipher
import Cryptlib.Primitives.WideBlockCipher.AEZ
import Cryptlib.Primitives.MAC.MAC
import Cryptlib.Primitives.KDF.KDF
import Cryptlib.Primitives.KDF.HKDF
import Cryptlib.Primitives.StreamCipher.StreamCipher
import Cryptlib.Primitives.StreamCipher.AES256CTR
import Cryptlib.Primitives.NIKE.NIKE
import Cryptlib.Primitives.NIKE.Schemes
import Cryptlib.Primitives.Hash.Sha512
import Cryptlib.Util.Bytes
import Cryptlib.Util.UniformHit

namespace Cryptlib.Protocols.Sphinx.NIKESphinx

open OracleComp OracleSpec ENNReal
open Cryptlib.Protocols.Sphinx.Constants
open Cryptlib.Protocols.Sphinx.Geometry (Geometry)
open Cryptlib.Protocols.Sphinx.Commands
open Cryptlib.Protocols.Sphinx.Types
open Cryptlib.Protocols.Sphinx.Common
open Cryptlib.Protocols.Sphinx.KDF (PacketKeys)
open Cryptlib.Primitives.Cipher.ChaCha20 (keystream32)
open Cryptlib.Primitives.WideBlockCipher (WideBlockCipher)
open Cryptlib.Primitives.MAC (MAC)
open Cryptlib.Primitives.KDF (KDF)
open Cryptlib.Primitives.StreamCipher (StreamCipher)
open Cryptlib.Primitives.NIKE.NIKE (NIKE telescopeElem telescopeSecret telescope_agree)
open Cryptlib.Primitives.Hash.Sha512 (sha512_256)
open Cryptlib.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)
open Cryptlib.Util.UniformHit (uniformHit_eq)

/-! # NIKE-Sphinx scheme type

Constructions and proofs are in `nike_sphinx_theorems.lean`. -/

/-- A `Sphinx` scheme whose header carries a re-blindable group element `Envelope`. -/
structure NIKESphinxScheme extends Cryptlib.Protocols.Sphinx.Interface.Sphinx where
  nike : NIKE
  Envelope : Type
  [envelopeDecEq : DecidableEq Envelope]
  /-- The header's group element. -/
  parseEnvelope : Vector UInt8 geometry.packetLength → Envelope
  /-- The blinding factor space. -/
  Factor : Type
  [factorFintype : Fintype Factor]
  [factorSampleable : SampleableType Factor]
  blind : Factor → Envelope → Envelope
  /-- Wrap-resistance (§4.3): if blinding `e` is a bijection, a uniform factor hits `target` with
  probability `1/|Factor|`. -/
  wrap_resistant : ∀ (e target : Envelope), Function.Bijective (blind · e) →
      Pr[= true | ($ᵗ Factor) >>= fun b => pure (decide (blind b e = target))] =
        (Fintype.card Factor : ℝ≥0∞)⁻¹ :=
    fun _ target hbij => uniformHit_eq hbij target
  /-- The envelope depends only on the starting `State`, not on the path or payload. -/
  envelope_indep : ∀ (hop0 hop1 : Types.PathHop) (rest0 rest1 : List Types.PathHop)
      (payload0 payload1 : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt0 pkt1 : Vector UInt8 geometry.packetLength) (st0' st1' : State),
    wrap (hop0 :: rest0) payload0 st = .ok pkt0 st0' →
    wrap (hop1 :: rest1) payload1 st = .ok pkt1 st1' →
    parseEnvelope pkt0 = parseEnvelope pkt1
end Cryptlib.Protocols.Sphinx.NIKESphinx
