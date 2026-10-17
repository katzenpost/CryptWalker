/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Sign.Ed25519_blinded
import Cryptlib.Primitives.Sign.Blindable
import Cryptlib.Util.UniformHit

/-! # BACAP unlinkability at Ed25519

Stated directly at the concrete types: going through `Blindable` makes Lean unfold `ZMod ℓ` on a
253-bit literal. -/

namespace Cryptlib.Protocols.BACAP.Ed25519Unlinkability

open OracleComp OracleSpec ENNReal
open Cryptlib.Primitives.Sign.Ed25519Blinded

/-- For a nonzero root secret `s`, a uniform blinding factor yields any box ID in the image with
probability `1/ℓ` (Echomix §4.3). -/
theorem ed25519_unlinkable [Fintype Scalar] [SampleableType Scalar] [DecidableEq PubBytes]
    (s : Scalar) (hs : s ≠ 0) {target : PubBytes}
    (ht : target ∈ Set.range (blindPub (publicKey s))) :
    Pr[= true | ($ᵗ Scalar) >>= fun f => pure (decide (blindPub (publicKey s) f = target))] =
      (Fintype.card Scalar : ℝ≥0∞)⁻¹ :=
  Cryptlib.Util.UniformHit.uniformHit_eq_of_injective (blindPub_injective s hs) ht

end Cryptlib.Protocols.BACAP.Ed25519Unlinkability
