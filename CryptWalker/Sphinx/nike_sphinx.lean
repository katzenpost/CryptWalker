/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.commands
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.sphinx
import CryptWalker.Sphinx.common
import CryptWalker.Sphinx.surb
import CryptWalker.Sphinx.kdf
import CryptWalker.Cipher.ChaCha20
import CryptWalker.WideBlockCipher.WideBlockCipher
import CryptWalker.WideBlockCipher.AEZ
import CryptWalker.MAC.MAC
import CryptWalker.KDF.KDF
import CryptWalker.KDF.HKDF
import CryptWalker.StreamCipher.StreamCipher
import CryptWalker.StreamCipher.AES256CTR
import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.Schemes
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes
import CryptWalker.Util.UniformHit

namespace CryptWalker.Sphinx.NIKESphinx

open OracleComp OracleSpec ENNReal
open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.KDF (PacketKeys)
open CryptWalker.Cipher.ChaCha20 (keystream32)
open CryptWalker.WideBlockCipher (WideBlockCipher)
open CryptWalker.MAC (MAC)
open CryptWalker.KDF (KDF)
open CryptWalker.StreamCipher (StreamCipher)
open CryptWalker.NIKE.NIKE (NIKE telescopeElem telescopeSecret telescope_agree)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)
open CryptWalker.Util.UniformHit (uniformHit_eq)

/-! # NIKE-Sphinx scheme type

Constructions and proofs are in `nike_sphinx_theorems.lean`. -/

/-- A `Sphinx` scheme whose header carries a re-blindable group element `Envelope`. -/
structure NIKESphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
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
end CryptWalker.Sphinx.NIKESphinx
