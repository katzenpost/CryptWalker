/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Hash.Hash

/-! # Cryptographic hash functions

Security properties are computational and cannot be fields. The laws relate the one-shot and
incremental interfaces: `hash_spec` (one call agrees with a fresh state) and `update_append`
(two chunks agree with their concatenation).
-/

structure Hash where
  /-- The running state of an incremental hash. -/
  State : Type

  name : String
  digestSize : Nat
  /-- The compression function's input width in bytes, used by HMAC for key padding. -/
  blockSize : Nat

  init     : State
  update   : State → ByteArray → State
  finalize : State → Vector UInt8 digestSize

  hash : ByteArray → Vector UInt8 digestSize

  hash_spec     : ∀ m, hash m = finalize (update init m)
  update_append : ∀ s a b, update (update s a) b = update s (a ++ b)

/-- The empty hash, to show `Hash` is inhabited. Not a hash. -/
instance : Inhabited Hash := ⟨{
  State      := Unit
  name       := "none"
  digestSize := 0
  blockSize  := 1
  init       := ()
  update     := fun _ _ => ()
  finalize   := fun _ => #v[]
  hash       := fun _ => #v[]
  hash_spec     := fun _ => rfl
  update_append := fun _ _ _ => rfl
}⟩

end CryptWalker.Hash.Hash
