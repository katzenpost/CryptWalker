/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged

/-! # Hedged ML-KEM-1024 -/

namespace Cryptlib.Primitives.KEM.MLKEMHedged

abbrev encaps1024Hedged := encapsHedged .MLKEM1024

/-- Hedged ML-KEM-1024 with the FIPS 203 expanded private key. -/
abbrev kemMLKEMHedged1024 := kem .MLKEM1024

/-- Hedged ML-KEM-1024 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEMHedged1024Seed := kemSeed .MLKEM1024

end Cryptlib.Primitives.KEM.MLKEMHedged
