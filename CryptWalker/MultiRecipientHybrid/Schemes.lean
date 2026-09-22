/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MultiRecipientHybrid.Adapter
import CryptWalker.KEM.MLKEM.MLKEM768
import CryptWalker.Cipher.AESGCMSIV
import CryptWalker.MKEM.Schemes

/-! # A concrete `MultiRecipientHybrid`: ML-KEM-768, AES-256-GCM-SIV, BLAKE2b-256

`hybridMLKEM768 := hybridOfKEM CryptWalker.KEM.MLKEM768.kemMLKEM768 …`: a genuine,
post-quantum (ML-KEM-768, NIST category 3) instance, needing no McEliece to get a real smoke test —
McEliece isn't implemented in CryptWalker. There is no `hpqc` construction to compare this against
either: `hpqc`'s only multi-recipient scheme is the NIKE-based `MKEM`, which cannot be built from a
plain KEM (see `MultiRecipientHybrid`'s module doc). Swapping in a future Classic McEliece `KEM`
instance here needs no change to `MultiRecipientHybrid` or `Adapter.hybridOfKEM` themselves. -/

namespace CryptWalker.MultiRecipientHybrid.Schemes

open CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid (MultiRecipientHybrid)
open CryptWalker.MultiRecipientHybrid.Adapter (hybridOfKEM)
open CryptWalker.MKEM.Schemes (blake2b256Scheme)

/-- ML-KEM-768, sealed with AES-256-GCM-SIV, keyed by BLAKE2b-256. -/
def hybridMLKEM768 : MultiRecipientHybrid :=
  hybridOfKEM CryptWalker.KEM.MLKEM768.kemMLKEM768 CryptWalker.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

end CryptWalker.MultiRecipientHybrid.Schemes
