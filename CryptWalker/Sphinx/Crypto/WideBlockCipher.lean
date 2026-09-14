/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.AEZCorrectness

namespace CryptWalker.Sphinx.Crypto.WideBlockCipher

/-! # Wide-block ciphers, generically

The same shape as `NIKE`, `KEM`, `Hash`, `HKDF`, `StreamCipher` and `MAC`: a plain structure whose
laws are fields, so no instance can exist without discharging them.

A wide-block cipher, in the sense Sphinx needs, is deliberately simple: it encrypts and decrypts
one arbitrarily large block at a time — the whole payload, not fixed-size chunks a caller has to
manage — so `encrypt`/`decrypt` take a plain `ByteArray` of any size, not a `Vector UInt8 n`.

## What can and cannot be a law here

Pseudorandom-permutation security (that `encrypt key` is indistinguishable from a uniformly random
permutation without `key`) is computational, adversary-quantified, and cannot be a struct field —
same reasoning as `Hash.lean`'s discussion of collision resistance. What *is* statable, and is
exactly what Sphinx's completeness proof needs, is the one purely structural guarantee any real
cipher (AEZ today, Lioness or another wide-block construction later) must satisfy regardless of
its internals: `decrypt` undoes `encrypt`, and both preserve length. This lets every proof about
`wrap`/`unwrap` cite `roundTrip` as a black box, never AEZ's (or any other cipher's) own internal
construction. -/

structure WideBlockCipher where
  keySize : Nat
  ivSize  : Nat

  /-- Encrypts one block of any size ≥ 16 bytes, no chunking exposed to the caller. -/
  encrypt : Array UInt8 → ByteArray → ByteArray → ByteArray
  decrypt : Array UInt8 → ByteArray → ByteArray → ByteArray

  encrypt_size : ∀ key iv msg, (encrypt key iv msg).size = msg.size
  decrypt_size : ∀ key iv msg, (decrypt key iv msg).size = msg.size

  /-- **Completeness**: decrypting an encrypted block always recovers it, for any block of at
  least 16 bytes — the size every real Sphinx payload (`payloadTagLength + forwardPayloadLength`)
  satisfies. No hypothesis on `key`/`iv` width: like AEZ's own `sprpDecrypt_sprpEncrypt`, this
  holds unconditionally in `key`/`iv`, only the message needs a minimum size. -/
  roundTrip : ∀ key iv msg, 16 ≤ msg.size → decrypt key iv (encrypt key iv msg) = msg

/-- The empty wide-block cipher: a placeholder so `WideBlockCipher` is demonstrably inhabited.
Obviously not a cipher (the identity function, satisfies every law trivially). -/
instance : Inhabited WideBlockCipher := ⟨{
  keySize := 0
  ivSize  := 0
  encrypt := fun _ _ msg => msg
  decrypt := fun _ _ msg => msg
  encrypt_size := fun _ _ _ => rfl
  decrypt_size := fun _ _ _ => rfl
  roundTrip := fun _ _ _ _ => rfl
}⟩

/-- AEZ, as a `WideBlockCipher`: `sprpEncrypt`/`sprpDecrypt` and the already-proved
`sprpEncrypt_size`/`sprpDecrypt_size`/`sprpDecrypt_sprpEncrypt` from `AEZCorrectness.lean`,
unchanged — this instance costs no new proof. `keySize`/`ivSize` record the widths Sphinx's own
`Geometry`/`Constants` actually use (`sprpKeyMaterialLength = 48`, the shared 16-byte IV); nothing
in `encrypt`/`decrypt`/the laws above actually constrains callers to those widths, since AEZ's
`initState` accepts key material of any length. -/
def aez : WideBlockCipher where
  keySize := 48
  ivSize  := 16
  encrypt := CryptWalker.Sphinx.Crypto.AEZ.sprpEncrypt
  decrypt := CryptWalker.Sphinx.Crypto.AEZ.sprpDecrypt
  encrypt_size := CryptWalker.Sphinx.Crypto.AEZ.sprpEncrypt_size
  decrypt_size := CryptWalker.Sphinx.Crypto.AEZ.sprpDecrypt_size
  roundTrip := fun key iv msg h => CryptWalker.Sphinx.Crypto.AEZ.sprpDecrypt_sprpEncrypt key iv msg h

end CryptWalker.Sphinx.Crypto.WideBlockCipher
