/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.MAC

/-! # Message authentication codes

`keySize` is informational; `mac` accepts any key length. Unforgeability is computational, so
there are no law fields. -/

structure MAC where
  keySize : Nat
  tagSize : Nat

  mac : ByteArray → ByteArray → Vector UInt8 tagSize

/-- The empty MAC, to show `MAC` is inhabited. Not a MAC. -/
instance : Inhabited MAC := ⟨{
  keySize := 0
  tagSize := 0
  mac := fun _ _ => #v[]
}⟩

end Cryptlib.Primitives.MAC
