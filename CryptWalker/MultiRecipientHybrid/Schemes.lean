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

`hybridMLKEM768X25519Blake2b` is the same over `kemMLKEM768X25519Blake2b`, whose X25519 half uses
the deployed `blake2b-xof` adapter PRF: byte-compatible with `hpqc`'s `kem/mrhybrid` over its
registered `"MLKEM768-X25519"`. `gen_multirecipient_hybrid_vectors.lean` and
`multirecipient_hybrid_test.lean` cross-check the two. (`hpqc`'s NIKE-based `MKEM` is a different
construction, which a KEM cannot instantiate; see `MultiRecipientHybrid`'s module doc.) Swapping in a
future Classic McEliece `KEM`, alone or hybridized the same way, needs no change to
`MultiRecipientHybrid` or `Adapter.hybridOfKEM` themselves. -/

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

/-- As `hybridMLKEM768X25519`, over the deployed `blake2b-xof` X25519 adapter PRF: `hpqc`'s
`kem/mrhybrid` over `"MLKEM768-X25519"`. -/
def hybridMLKEM768X25519Blake2b : MultiRecipientHybrid :=
  hybridOfKEM CryptWalker.KEM.kemMLKEM768X25519Blake2b CryptWalker.Cipher.AESGCMSIV.Scheme
    blake2b256Scheme rfl

end CryptWalker.MultiRecipientHybrid.Schemes
