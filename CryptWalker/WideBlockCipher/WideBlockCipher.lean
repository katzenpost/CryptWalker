/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.WideBlockCipher

/-! # Wide-block ciphers

Encrypt and decrypt one arbitrarily long block. PRP security is computational and not stated;
the laws are length preservation and round trip. -/

structure WideBlockCipher where
  keySize : Nat
  ivSize  : Nat

  /-- Encrypts one block of any size ≥ 16 bytes. -/
  encrypt : Array UInt8 → ByteArray → ByteArray → ByteArray
  decrypt : Array UInt8 → ByteArray → ByteArray → ByteArray

  encrypt_size : ∀ key iv msg, (encrypt key iv msg).size = msg.size
  decrypt_size : ∀ key iv msg, (decrypt key iv msg).size = msg.size

  /-- Decryption inverts encryption for blocks of at least 16 bytes, for any key and IV. -/
  roundTrip : ∀ key iv msg, 16 ≤ msg.size → decrypt key iv (encrypt key iv msg) = msg

/-- The identity, showing the laws are satisfiable. Provides no security. -/
instance : Inhabited WideBlockCipher := ⟨{
  keySize := 0
  ivSize  := 0
  encrypt := fun _ _ msg => msg
  decrypt := fun _ _ msg => msg
  encrypt_size := fun _ _ _ => rfl
  decrypt_size := fun _ _ _ => rfl
  roundTrip := fun _ _ _ _ => rfl
}⟩

end CryptWalker.WideBlockCipher
