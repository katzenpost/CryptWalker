/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Sign.Blindable
import CryptWalker.Util.UniformHit

/-! # BACAP unlinkability, at Ed25519

`Blindable.blind_injective` is a field every scheme supplies; for Ed25519 it holds because the
basepoint has order exactly `ℓ` (`Ed25519Blinded.blindPub_injective`). With it, a uniform blinding
factor hits each box ID in the orbit of a regular root key with probability `1/ℓ`
(`Blindable.blind_unlinkable`). This restates that at the concrete types, applying
`uniformHit_eq_of_injective` directly: going through the abstract `Blindable` record makes Lean
unfold `ZMod ℓ` on a 253-bit literal.

No assumption beyond `p_prime` and `ell_prime`. -/

namespace CryptWalker.BACAP.Ed25519Unlinkability

open OracleComp OracleSpec ENNReal
open CryptWalker.Sign.Ed25519Blinded

/-- **BACAP unlinkability at Ed25519** (Echomix §4.3, under uniformly random blinding factors).
For a nonzero root secret `s`, a uniformly drawn blinding factor produces any given box ID in the
image with probability exactly `1/ℓ`. -/
theorem ed25519_unlinkable [Fintype Scalar] [SampleableType Scalar] [DecidableEq PubBytes]
    (s : Scalar) (hs : s ≠ 0) {target : PubBytes}
    (ht : target ∈ Set.range (blindPub (publicKey s))) :
    Pr[= true | ($ᵗ Scalar) >>= fun f => pure (decide (blindPub (publicKey s) f = target))] =
      (Fintype.card Scalar : ℝ≥0∞)⁻¹ :=
  CryptWalker.Util.UniformHit.uniformHit_eq_of_injective (blindPub_injective s hs) ht

end CryptWalker.BACAP.Ed25519Unlinkability
