/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MultiRecipientHybrid.Adapter
import CryptWalker.KEM.MLKEM.MLKEM768
import CryptWalker.KEM.Schemes
import CryptWalker.Cipher.AESGCMSIV
import CryptWalker.MKEM.Schemes

/-! # Concrete `MultiRecipientHybrid` instances -/

namespace CryptWalker.MultiRecipientHybrid.Schemes

open CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid (MultiRecipientHybrid)
open CryptWalker.MultiRecipientHybrid.Adapter (hybridOfKEM)
open CryptWalker.MKEM.Schemes (blake2b256Scheme)

/-- ML-KEM-768, sealed with AES-256-GCM-SIV, keyed by BLAKE2b-256. -/
def hybridMLKEM768 : MultiRecipientHybrid :=
  hybridOfKEM CryptWalker.KEM.MLKEM768.kemMLKEM768 CryptWalker.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

/-- X25519 combined with ML-KEM-768, sealed with AES-256-GCM-SIV, keyed by BLAKE2b-256. -/
def hybridMLKEM768X25519 : MultiRecipientHybrid :=
  hybridOfKEM CryptWalker.KEM.kemMLKEM768X25519 CryptWalker.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

/-- As `hybridMLKEM768X25519`, with the `blake2b-xof` X25519 adapter PRF. -/
def hybridMLKEM768X25519Blake2b : MultiRecipientHybrid :=
  hybridOfKEM CryptWalker.KEM.kemMLKEM768X25519Blake2b CryptWalker.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

end CryptWalker.MultiRecipientHybrid.Schemes
