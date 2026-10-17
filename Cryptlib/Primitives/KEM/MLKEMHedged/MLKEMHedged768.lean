/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged
import Cryptlib.Primitives.KEM.MLKEM.MLKEM768

/-! # Hedged ML-KEM-768 -/

namespace Cryptlib.Primitives.KEM.MLKEMHedged

abbrev encaps768Hedged := encapsHedged .MLKEM768

theorem encaps768Hedged_eq_encaps768_hashH
    (ek : _root_.MLKEM.EncapsulationKey MLKEM768.params MLKEM768.encoding) (m : _root_.MLKEM.Message) :
    encaps768Hedged ek m = MLKEM768.encaps768 ek (MLKEM768.hashH (Cryptlib.Util.Bytes.ofVector m)) :=
  encapsHedged_eq_encaps_hashH .MLKEM768 ek m

/-- Hedged ML-KEM-768 with the FIPS 203 expanded private key. -/
abbrev kemMLKEMHedged768 := kem .MLKEM768

/-- Hedged ML-KEM-768 with the `ek ‖ d ‖ z` seed private key. -/
abbrev kemMLKEMHedged768Seed := kemSeed .MLKEM768

end Cryptlib.Primitives.KEM.MLKEMHedged
