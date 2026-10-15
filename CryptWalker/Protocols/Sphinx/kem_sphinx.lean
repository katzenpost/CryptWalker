/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.Sphinx.constants
import CryptWalker.Protocols.Sphinx.geometry
import CryptWalker.Protocols.Sphinx.commands
import CryptWalker.Protocols.Sphinx.types
import CryptWalker.Protocols.Sphinx.sphinx
import CryptWalker.Protocols.Sphinx.common
import CryptWalker.Protocols.Sphinx.nike_sphinx_theorems
import CryptWalker.Protocols.Sphinx.surb
import CryptWalker.WideBlockCipher.WideBlockCipher
import CryptWalker.WideBlockCipher.AEZ
import CryptWalker.MAC.MAC
import CryptWalker.KDF.KDF
import CryptWalker.KDF.HKDF
import CryptWalker.Protocols.Sphinx.kdf
import CryptWalker.StreamCipher.StreamCipher
import CryptWalker.StreamCipher.AES256CTR
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Schemes
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Protocols.Sphinx.KEMSphinx

open CryptWalker.Protocols.Sphinx.Constants
open CryptWalker.Protocols.Sphinx.Geometry (Geometry)
open CryptWalker.Protocols.Sphinx.Commands
open CryptWalker.Protocols.Sphinx.Types
open CryptWalker.Protocols.Sphinx.Common
open CryptWalker.Protocols.Sphinx.NIKESphinx (HopKeys deriveHopKeys)
open CryptWalker.WideBlockCipher (WideBlockCipher)
open CryptWalker.MAC (MAC)
open CryptWalker.KDF (KDF)
open CryptWalker.StreamCipher (StreamCipher)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)

/-! # KEM-Sphinx scheme type

Constructions and proofs are in `kem_sphinx_theorems.lean`. -/

structure KEMSphinxScheme extends CryptWalker.Protocols.Sphinx.Interface.Sphinx where
  kem : KEM
  /-- Not wrap-resistant: any target routing-info block is reachable by some ciphertext. -/
  not_wrap_resistant : ∀ (key iv target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (stream.keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (stream.keystream key iv target.size) target

end CryptWalker.Protocols.Sphinx.KEMSphinx
