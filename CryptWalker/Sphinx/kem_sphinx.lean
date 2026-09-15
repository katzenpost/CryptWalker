/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.commands
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.interface
import CryptWalker.Sphinx.common
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.surb
import CryptWalker.Sphinx.Crypto.stream
import CryptWalker.WideBlockCipher.WideBlockCipher
import CryptWalker.WideBlockCipher.AEZ
import CryptWalker.Sphinx.Crypto.mac
import CryptWalker.Sphinx.Crypto.generic_kdf
import CryptWalker.Sphinx.Crypto.stream_cipher
import CryptWalker.KEM.KEM
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
open CryptWalker.WideBlockCipher (WideBlockCipher)
open CryptWalker.Sphinx.Crypto.MAC (MAC)
open CryptWalker.Sphinx.Crypto.GenericKDF (KDF)
open CryptWalker.Sphinx.Crypto.StreamCipher (StreamCipher)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)

/-! # KEM-Sphinx scheme type

`KEMSphinxScheme` — the `Sphinx.Interface.Sphinx` extension for the KEM path, adding the `kem`
field and the (perhaps counterintuitive, but expected) `not_wrap_resistant` fact that
distinguishes it from `NIKESphinxScheme`. See `kem_sphinx_theorems.lean` for `createKEMHeader`/
`newKEMPacket`/`wrapKEM`/`unwrapKEM`, every supporting lemma, the completeness proof
(`wrapKEM_unwrapKEM_complete_valid`), the builders (`kemSphinxSchemeOf`/`kemSphinxScheme`) that
actually construct one of these, and the `unwrapKEM_routingInfoBlock_not_wrap_resistant` proof
backing the fact below. -/

structure KEMSphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
  kem : KEM
  /-- **Not wrap-resistant** — the inverse of `NIKESphinxScheme.wrap_resistant`: a known-key
  adversary hits any target routing-info block with certainty, not merely `1/N`. See
  `unwrapKEM_routingInfoBlock_not_wrap_resistant` (in `kem_sphinx_theorems.lean`) for why. Holds
  for any `stream : StreamCipher`, not just a hardcoded one. -/
  not_wrap_resistant : ∀ (key iv target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (stream.keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (stream.keystream key iv target.size) target

end CryptWalker.Sphinx.KEMSphinx
