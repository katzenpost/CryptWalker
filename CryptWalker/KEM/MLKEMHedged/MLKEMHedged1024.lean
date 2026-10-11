/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEMHedged.MLKEMHedged

/-! # Hedged ML-KEM-1024 -/

namespace CryptWalker.KEM.MLKEMHedged

abbrev encaps1024Hedged := encapsHedged .MLKEM1024

/-- Hedged ML-KEM-1024 with the FIPS 203 expanded private key. -/
abbrev kemMLKEMHedged1024 := kem .MLKEM1024

/-- Hedged ML-KEM-1024 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEMHedged1024Seed := kemSeed .MLKEM1024

end CryptWalker.KEM.MLKEMHedged
