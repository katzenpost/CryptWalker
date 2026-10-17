/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEM.MLKEM

namespace Cryptlib.Primitives.KEM.MLKEM1024

/-- ML-KEM-1024 with the FIPS 203 expanded private key. -/
abbrev kemMLKEM1024 := FIPS203.kem .MLKEM1024

/-- ML-KEM-1024 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEM1024Seed := FIPS203.kemSeed .MLKEM1024

end Cryptlib.Primitives.KEM.MLKEM1024
