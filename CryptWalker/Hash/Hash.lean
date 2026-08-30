/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Hash.Hash

/-! # Cryptographic hash functions

The same shape as `NIKE`, `KEM` and `Signature`: a plain structure whose laws are fields, so no
instance can exist without discharging them.

## What can and cannot be a law here

Collision resistance, preimage resistance and indifferentiability are all computational — they
quantify over adversaries and negligible functions — so none of them can be a field. Attempting
one would produce a proposition no instance could ever discharge.

What *is* statable, and is exactly what callers depend on, is the relationship between the
one-shot and incremental interfaces:

* `hash_spec` — hashing a message in one call agrees with feeding it to a fresh state.
* `update_append` — feeding data in two chunks agrees with feeding the concatenation.

`update_append` is the one that earns its keep. HKDF reads a single output stream sliced across
several HMAC blocks — BACAP's KDF chain reads 96 bytes as `H ‖ E ‖ K` spanning two — and getting
that boundary wrong is precisely the bug hpqc's `long_okm_to_catch_streaming_bugs` vector exists
to catch. Here it is a proof obligation rather than a test.

Note that `digestSize` needs no law: `Vector UInt8 digestSize` makes the width a type-level fact.
-/

structure Hash where
  /-- The running state of an incremental hash. -/
  State : Type

  name : String
  digestSize : Nat
  /-- The compression function's input width, in bytes. Not constrained by any law here, but
  HMAC needs it to size its key padding. -/
  blockSize : Nat

  init     : State
  update   : State → ByteArray → State
  finalize : State → Vector UInt8 digestSize

  /-- The one-shot interface. -/
  hash : ByteArray → Vector UInt8 digestSize

  hash_spec     : ∀ m, hash m = finalize (update init m)
  update_append : ∀ s a b, update (update s a) b = update s (a ++ b)

/-- The empty hash: a placeholder so `Hash` is demonstrably inhabited. Obviously not a hash. -/
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
