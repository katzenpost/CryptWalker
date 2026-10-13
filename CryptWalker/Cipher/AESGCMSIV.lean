/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AEAD
import CryptWalker.Cipher.AES
import CryptWalker.Cipher.Polyval
import CryptWalker.Util.Bytes

namespace CryptWalker.Cipher.AESGCMSIV

open CryptWalker.Cipher.AEAD
open CryptWalker.Cipher.AES
open CryptWalker.Cipher.Polyval
open CryptWalker.Util.Bytes

/-! # AES-256-GCM-SIV

RFC 8452, 256-bit keys. Nonce-misuse resistant: a repeated nonce reveals only whether two
plaintexts were equal.

1. Derive a POLYVAL key and a message-encryption key from the key and nonce.
2. Tag: POLYVAL over padded AD, padded plaintext and the lengths, XORed with the nonce, top bit
   cleared, then encrypted under the message-encryption key.
3. Encrypt the plaintext in CTR mode, with the counter seeded from the tag.
-/

/-- The key-generating key. -/
abbrev Key := Vector UInt8 32
abbrev Nonce := Vector UInt8 12
abbrev Block := Vector UInt8 16

/-- Little-endian `u32`. -/
private def le32 (i : Nat) : Vector UInt8 4 :=
  Vector.ofFn fun j : Fin 4 => UInt8.ofNat ((i >>> (8 * j.val)) % 256)

/-- Little-endian `u64`. -/
private def le64 (i : Nat) : Vector UInt8 8 :=
  Vector.ofFn fun j : Fin 8 => UInt8.ofNat ((i >>> (8 * j.val)) % 256)

/-- The first eight bytes of the encryption of derivation block `LE32(i) ‖ nonce`. -/
private def subKey (rk : Array UInt8) (n : Nonce) (i : Nat) : Vector UInt8 8 :=
  ((encryptBlock rk (le32 i ++ n)).take 8).cast (by omega)

/-- The POLYVAL key, from derivation blocks 0 and 1. -/
private def authKey (key : Key) (n : Nonce) : Block :=
  let rk := expandKey key
  subKey rk n 0 ++ subKey rk n 1

/-- The message-encryption key, from derivation blocks 2 through 5. -/
private def encKey (key : Key) (n : Nonce) : Vector UInt8 32 :=
  let rk := expandKey key
  subKey rk n 2 ++ subKey rk n 3 ++ subKey rk n 4 ++ subKey rk n 5

/-- Zero-pad to a block boundary. -/
private def pad16 (b : ByteArray) : ByteArray :=
  b ++ ⟨Array.replicate ((16 - b.size % 16) % 16) 0⟩

/-- XOR the nonce into the POLYVAL output and clear the top bit of the last byte. -/
private def maskWithNonce (s : Block) (n : Nonce) : Block :=
  let x : Block := Vector.ofFn fun i : Fin 16 => s[i.val]'i.isLt ^^^ n.toArray.getD i.val 0
  x.set 15 (x[15] &&& 0x7f)

/-- The tag: POLYVAL over `pad(ad) ‖ pad(pt) ‖ LE64(|ad| in bits) ‖ LE64(|pt| in bits)`, masked
with the nonce, then one forward AES call. -/
private def tagOf (key : Key) (n : Nonce) (ad pt : ByteArray) : Block :=
  let lengthBlock := ofVector (le64 (ad.size * 8) ++ le64 (pt.size * 8))
  let s := polyval (authKey key n) (pad16 ad ++ pad16 pt ++ lengthBlock)
  encryptBlockWithKey (encKey key n) (maskWithNonce s n)

/-- The initial counter block: the tag with the top bit of its last byte set. Bytes past the
sixteenth are ignored; a short input is zero-padded. -/
private def counterBlock (tag : ByteArray) : Block :=
  let x : Block := Vector.ofFn fun i : Fin 16 => tag.data.getD i.val 0
  x.set 15 (x[15] ||| 0x80)

/-- The `i`th keystream block: the counter block with its first four bytes, read little-endian,
incremented by `i` modulo `2^32`. -/
private def keystreamBlock (rk : Array UInt8) (ctr : Block) (i : Nat) : Block :=
  let base := ctr[0].toNat ||| (ctr[1].toNat <<< 8) ||| (ctr[2].toNat <<< 16) ||| (ctr[3].toNat <<< 24)
  let rest : Vector UInt8 12 := Vector.ofFn fun j : Fin 12 => ctr.toArray.getD (j.val + 4) 0
  encryptBlock rk (le32 (base + i) ++ rest)

/-- `len` bytes of keystream. -/
private def keystream (ek : Vector UInt8 32) (ctr : Block) (len : Nat) : ByteArray :=
  let rk := expandKey ek
  ((List.range ((len + 15) / 16)).foldl
    (fun out i => out ++ ofVector (keystreamBlock rk ctr i)) ByteArray.empty).extract 0 len

/-- XOR a keystream into a buffer. -/
private def xorKeystream (ks : ByteArray) (d : ByteArray) : ByteArray :=
  -- `ByteArray.data` copies, so convert once rather than per byte
  let k := ks.data
  ⟨d.data.mapIdx fun i b => b ^^^ k.getD i 0⟩

/-- CTR mode: the same operation encrypts and decrypts. -/
private def ctrXor (ek : Vector UInt8 32) (ctr : Block) (d : ByteArray) : ByteArray :=
  xorKeystream (keystream ek ctr d.size) d

/-! ### CTR mode is its own inverse -/

@[simp] private theorem size_xorKeystream (ks d : ByteArray) :
    (xorKeystream ks d).size = d.size := by
  show (d.data.mapIdx _).size = d.size
  simp

@[simp] private theorem size_ctrXor (ek : Vector UInt8 32) (ctr : Block) (d : ByteArray) :
    (ctrXor ek ctr d).size = d.size := by
  simp [ctrXor]

/-- XORing the same keystream twice is the identity. -/
private theorem ctrXor_ctrXor (ek : Vector UInt8 32) (ctr : Block) (d : ByteArray) :
    ctrXor ek ctr (ctrXor ek ctr d) = d := by
  show xorKeystream (keystream ek ctr (ctrXor ek ctr d).size) (ctrXor ek ctr d) = d
  rw [size_ctrXor]
  apply ByteArray.ext
  apply Array.ext
  · simp [xorKeystream, ctrXor]
  · intro i h1 h2
    simp only [xorKeystream, ctrXor, Array.getElem_mapIdx]
    rw [UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

/-! ### Sealing and opening -/

/-- Compute the tag, encrypt under a counter seeded by it, then append the tag. -/
def encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) : ByteArray :=
  let tag := ofVector (tagOf key n ad pt)
  ctrXor (encKey key n) (counterBlock tag) pt ++ tag

/-- Split off the tag, decrypt, recompute the tag and accept only on equality. The comparison is
not constant time. -/
def decrypt (key : Key) (n : Nonce) (ad ct : ByteArray) : Option ByteArray :=
  if ct.size < 16 then none
  else
    let tag := ct.extract (ct.size - 16) ct.size
    let body := ct.extract 0 (ct.size - 16)
    let pt := ctrXor (encKey key n) (counterBlock tag) body
    if (ofVector (tagOf key n ad pt)).data = tag.data then some pt else none

/-! ### The `AEAD` instance -/

private theorem size_encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) :
    (encrypt key n ad pt).size = pt.size + 16 := by
  simp [encrypt, ByteArray.size_append]

/-- Decrypting a `body ‖ tag` concatenation. -/
private theorem decrypt_append (key : Key) (n : Nonce) (ad body tag : ByteArray)
    (h16 : tag.size = 16) :
    decrypt key n ad (body ++ tag) =
      (if (ofVector (tagOf key n ad (ctrXor (encKey key n) (counterBlock tag) body))).data
            = tag.data
       then some (ctrXor (encKey key n) (counterBlock tag) body)
       else none) := by
  have hs : (body ++ tag).size = body.size + 16 := by rw [ByteArray.size_append, h16]
  have hcut : (body ++ tag).size - 16 = body.size := by omega
  have hleft : (body ++ tag).extract 0 ((body ++ tag).size - 16) = body := by
    rw [hcut, extract_append_left]
  have hright : (body ++ tag).extract ((body ++ tag).size - 16) (body ++ tag).size = tag := by
    rw [hcut, hs, show body.size + 16 = body.size + tag.size from by rw [h16],
        extract_append_right]
  rw [decrypt, if_neg (by omega)]
  simp only [hleft, hright]

private theorem decrypt_encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) :
    decrypt key n ad (encrypt key n ad pt) = some pt := by
  rw [encrypt, decrypt_append _ _ _ _ _ (size_ofVector _), ctrXor_ctrXor, if_pos rfl]

theorem decrypt_sound (key : Key) (n : Nonce) (ad ct pt : ByteArray)
    (h : decrypt key n ad ct = some pt) : encrypt key n ad pt = ct := by
  by_cases hlen : ct.size < 16
  · rw [decrypt, if_pos hlen] at h
    exact absurd h (by simp)
  · have hsplit : ct.extract 0 (ct.size - 16) ++ ct.extract (ct.size - 16) ct.size = ct :=
      append_extract ct (ct.size - 16) (by omega)
    have h16 : (ct.extract (ct.size - 16) ct.size).size = 16 := by
      rw [ByteArray.size_extract]; omega
    rw [← hsplit, decrypt_append _ _ _ _ _ h16] at h
    split at h
    · rename_i htag
      rw [← Option.some.inj h, encrypt, ByteArray.ext htag, ctrXor_ctrXor]
      exact hsplit
    · exact absurd h (by simp)

/-- AES-256-GCM-SIV as an `AEAD`. -/
def Scheme : AEAD where
  Key := Key

  name      := "AES-256-GCM-SIV"
  keySize   := 32
  nonceSize := 12
  tagSize   := 16

  -- RFC 8452 §6.
  maxPlaintextSize := 2 ^ 36
  maxADSize        := 2 ^ 36

  keyFromBytes := id

  encrypt := encrypt
  decrypt := decrypt

  size_encrypt    := size_encrypt
  decrypt_encrypt := decrypt_encrypt
  decrypt_sound   := decrypt_sound

end CryptWalker.Cipher.AESGCMSIV
