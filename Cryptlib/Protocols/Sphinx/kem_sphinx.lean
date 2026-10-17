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
import Cryptlib.Protocols.Sphinx.nike_sphinx_theorems
import Cryptlib.Protocols.Sphinx.surb
import Cryptlib.Primitives.WideBlockCipher.WideBlockCipher
import Cryptlib.Primitives.WideBlockCipher.AEZ
import Cryptlib.Primitives.MAC.MAC
import Cryptlib.Primitives.KDF.KDF
import Cryptlib.Primitives.KDF.HKDF
import Cryptlib.Protocols.Sphinx.kdf
import Cryptlib.Primitives.StreamCipher.StreamCipher
import Cryptlib.Primitives.StreamCipher.AES256CTR
import Cryptlib.Primitives.KEM.KEM
import Cryptlib.Primitives.KEM.Schemes
import Cryptlib.Primitives.Hash.Sha512
import Cryptlib.Util.Bytes

namespace Cryptlib.Protocols.Sphinx.KEMSphinx

open Cryptlib.Protocols.Sphinx.Constants
open Cryptlib.Protocols.Sphinx.Geometry (Geometry)
open Cryptlib.Protocols.Sphinx.Commands
open Cryptlib.Protocols.Sphinx.Types
open Cryptlib.Protocols.Sphinx.Common
open Cryptlib.Protocols.Sphinx.NIKESphinx (HopKeys deriveHopKeys)
open Cryptlib.Primitives.WideBlockCipher (WideBlockCipher)
open Cryptlib.Primitives.MAC (MAC)
open Cryptlib.Primitives.KDF (KDF)
open Cryptlib.Primitives.StreamCipher (StreamCipher)
open Cryptlib.Primitives.KEM.KEM (KEM)
open Cryptlib.Primitives.Hash.Sha512 (sha512_256)
open Cryptlib.Util.Bytes (ofVector extract_append_le extract_append_of_le extract_append_of_ge
  extract_append_left extract_append_right append_extract)

/-! # KEM-Sphinx scheme type

Constructions and proofs are in `kem_sphinx_theorems.lean`. -/

structure KEMSphinxScheme extends Cryptlib.Protocols.Sphinx.Interface.Sphinx where
  kem : KEM
  /-- Not wrap-resistant: any target routing-info block is reachable by some ciphertext. -/
  not_wrap_resistant : ∀ (key iv target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (stream.keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (stream.keystream key iv target.size) target

end Cryptlib.Protocols.Sphinx.KEMSphinx
