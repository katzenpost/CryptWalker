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

`NIKESphinxScheme` — the `Sphinx.Interface.Sphinx` extension for the NIKE path, adding the
re-blindable-envelope structure (`Envelope`/`Factor`/`blind`/`wrap_resistant`/`envelope_indep`)
`Sphinx.WrapResistance`'s bound needs. See `nike_sphinx_theorems.lean` for `createHeader`/
`newNIKEPacket`/`wrapNIKE`/`unwrapNIKE`, every supporting lemma, the completeness proof
(`wrapNIKE_unwrapNIKE_complete_valid`), and the builders (`nikeSphinxCore`/`nikeSphinxSchemeOf`/
`nikeSphinxScheme`) that actually construct one of these. -/

/-- A `Sphinx` scheme whose header carries a re-blindable public-key element: `Envelope` is that
element's type (`parseEnvelope` extracts it from a packet), `Factor` the space a fresh blinding
value is drawn from, `blind` the re-blinding action. `wrap_resistant` needs no per-instance proof
— it's `uniformHit_eq` specialized to `act := blind · e`, true automatically; its hypothesis
(`blind · e` bijective) is false only for a degenerate `e` a well-formed header never produces. -/
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
  /-- **Wrap-resistance**: whenever blinding by `e` is a bijection (the case for any `e` that
  generates the (sub)group a well-formed header's element lives in), a freshly drawn factor hits
  a chosen `target` with probability exactly `1/|Factor|`. -/
  wrap_resistant : ∀ (e target : Envelope), Function.Bijective (blind · e) →
      Pr[= true | ($ᵗ Factor) >>= fun b => pure (decide (blind b e = target))] =
        (Fintype.card Factor : ℝ≥0∞)⁻¹ :=
    fun _ target hbij => uniformHit_eq hbij target
  /-- **Envelope independence** (§4.4, exact rather than up to some advantage): the envelope
  depends only on `wrap`'s seed-stream draw, never on path/filler/payload, so two calls sharing a
  starting `State` produce byte-for-byte identical envelopes — no adversary can learn anything
  about the session's content from it alone. See `wrapNIKE_envelope_indep` (in
  `nike_sphinx_theorems.lean`) for why: the envelope is the client's own public key. -/
  envelope_indep : ∀ (hop0 hop1 : Types.PathHop) (rest0 rest1 : List Types.PathHop)
      (filler0 filler1 : ByteArray)
      (payload0 payload1 : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt0 pkt1 : Vector UInt8 geometry.packetLength) (st0' st1' : State),
    wrap (hop0 :: rest0) filler0 payload0 st = .ok pkt0 st0' →
    wrap (hop1 :: rest1) filler1 payload1 st = .ok pkt1 st1' →
    parseEnvelope pkt0 = parseEnvelope pkt1
end CryptWalker.Sphinx.NIKESphinx
