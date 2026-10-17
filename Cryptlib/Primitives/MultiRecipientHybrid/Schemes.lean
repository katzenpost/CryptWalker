/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.MultiRecipientHybrid.Adapter
import Cryptlib.Primitives.KEM.MLKEM.MLKEM768
import Cryptlib.Primitives.KEM.Schemes
import Cryptlib.Primitives.Cipher.AESGCMSIV
import Cryptlib.Primitives.MKEM.Schemes

/-! # Concrete `MultiRecipientHybrid` instances -/

namespace Cryptlib.Primitives.MultiRecipientHybrid.Schemes

open Cryptlib.Primitives.MultiRecipientHybrid.MultiRecipientHybrid (MultiRecipientHybrid)
open Cryptlib.Primitives.MultiRecipientHybrid.Adapter (hybridOfKEM)
open Cryptlib.Primitives.MKEM.Schemes (blake2b256Scheme)

/-- ML-KEM-768, sealed with AES-256-GCM-SIV, keyed by BLAKE2b-256. -/
def hybridMLKEM768 : MultiRecipientHybrid :=
  hybridOfKEM Cryptlib.Primitives.KEM.MLKEM768.kemMLKEM768 Cryptlib.Primitives.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

/-- X25519 combined with ML-KEM-768, sealed with AES-256-GCM-SIV, keyed by BLAKE2b-256. -/
def hybridMLKEM768X25519 : MultiRecipientHybrid :=
  hybridOfKEM Cryptlib.Primitives.KEM.kemMLKEM768X25519 Cryptlib.Primitives.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

/-- As `hybridMLKEM768X25519`, with the `blake2b-xof` X25519 adapter PRF. -/
def hybridMLKEM768X25519Blake2b : MultiRecipientHybrid :=
  hybridOfKEM Cryptlib.Primitives.KEM.kemMLKEM768X25519Blake2b Cryptlib.Primitives.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

end Cryptlib.Primitives.MultiRecipientHybrid.Schemes
