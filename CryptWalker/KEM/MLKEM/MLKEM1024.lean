/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM

namespace CryptWalker.KEM.MLKEM1024

/-- ML-KEM-1024 with the FIPS 203 expanded private key. -/
abbrev kemMLKEM1024 := FIPS203.kem .MLKEM1024

/-- ML-KEM-1024 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEM1024Seed := FIPS203.kemSeed .MLKEM1024

end CryptWalker.KEM.MLKEM1024
