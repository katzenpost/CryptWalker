/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MultiRecipientHybrid.Adapter
import CryptWalker.KEM.MLKEM.MLKEM768
import CryptWalker.KEM.Schemes
import CryptWalker.Cipher.AESGCMSIV
import CryptWalker.MKEM.Schemes

/-! # Concrete `MultiRecipientHybrid` instances

`hybridMLKEM768` is plain ML-KEM-768 (NIST category 3) — already post-quantum, and a real smoke
test with no McEliece needed, since McEliece isn't implemented in CryptWalker.

`hybridMLKEM768X25519` is the one that matters: `CryptWalker.KEM.kemMLKEM768X25519`, X25519
combined with ML-KEM-768 via the generic split-PRF combiner (`KEM.Combiner`, `KEM/Schemes.lean`),
same shape as `hpqc`'s `"MLKEM768-X25519"` — IND-CCA2 as long as *either* component is (Giacon,
Heuer & Poettering, Theorem 1; see `KEM/Schemes.lean`'s docstring on `kemMLKEM768X25519`). Since
`hybridOfKEM` is generic over any `KEM`, this needs no new proof: whatever `kemMLKEM768X25519`
already establishes about `Reliable`/`honestRoundTrip` carries straight through.

There is no `hpqc` construction to compare either instance against directly: `hpqc`'s only
multi-recipient scheme is the NIKE-based `MKEM`, which cannot be built from a plain (or hybrid)
KEM at all (see `MultiRecipientHybrid`'s module doc — no combine operation). Swapping in a future
Classic McEliece `KEM`, alone or hybridized the same way, needs no change to `MultiRecipientHybrid`
or `Adapter.hybridOfKEM` themselves. -/

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

end CryptWalker.MultiRecipientHybrid.Schemes
