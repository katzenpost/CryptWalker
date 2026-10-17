/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged

/-! # Hedged ML-KEM-512 -/

namespace Cryptlib.Primitives.KEM.MLKEMHedged

abbrev encaps512Hedged := encapsHedged .MLKEM512

/-- Hedged ML-KEM-512 with the FIPS 203 expanded private key. -/
abbrev kemMLKEMHedged512 := kem .MLKEM512

/-- Hedged ML-KEM-512 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEMHedged512Seed := kemSeed .MLKEM512

end Cryptlib.Primitives.KEM.MLKEMHedged
