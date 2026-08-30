/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Util.Combine

/-! # Shared machinery for combining two schemes

Both the KEM combiner and the signature combiner need the same two things: a way to split a
concatenated encoding back into its halves, and a way to run one component's state action
against half of a product state. They live here so the two combiners do not each define
`splitL`/`sliftL` in their own namespace — which makes every name ambiguous at any call site
that opens both.
-/

/-- Run a total state action against the left half of a product state. -/
def sliftL {σ₁ σ₂ α} (x : StateM σ₁ α) : StateM (σ₁ × σ₂) α :=
  fun (s₁, s₂) => ((x s₁).1, ((x s₁).2, s₂))

/-- Run a total state action against the right half of a product state. -/
def sliftR {σ₁ σ₂ α} (x : StateM σ₂ α) : StateM (σ₁ × σ₂) α :=
  fun (s₁, s₂) => ((x s₂).1, (s₁, (x s₂).2))

/-- The first `a` bytes of a concatenation. -/
def splitL {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 a :=
  (v.take a).cast (by omega)

/-- The remaining `b` bytes of a concatenation. -/
def splitR {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 b :=
  (v.drop a).cast (by omega)

theorem splitL_append {a b : Nat} (v : Vector UInt8 a) (w : Vector UInt8 b) :
    splitL (v ++ w) = v := by
  apply Vector.ext; intro i hi; simp [splitL, hi]

theorem splitR_append {a b : Nat} (v : Vector UInt8 a) (w : Vector UInt8 b) :
    splitR (v ++ w) = w := by
  apply Vector.ext; intro i hi; simp [splitR]

end CryptWalker.Util.Combine
