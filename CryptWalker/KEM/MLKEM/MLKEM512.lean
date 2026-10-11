/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM

namespace CryptWalker.KEM.MLKEM512

/-- ML-KEM-512 with the FIPS 203 expanded private key. -/
abbrev kemMLKEM512 := FIPS203.kem .MLKEM512

/-- ML-KEM-512 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEM512Seed := FIPS203.kemSeed .MLKEM512

end CryptWalker.KEM.MLKEM512
