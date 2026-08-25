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

RFC 8452, at the 256-bit key size. This is the AEAD BACAP encrypts pigeonhole boxes with:
`hpqc/bacap/bacap_impl.go` seals a box payload under a per-box key, with the first twelve bytes
of the box ID as the nonce and the whole 32-byte box ID as associated data.

## Why the misuse-resistant mode, and not GCM

A BACAP box ID is a deterministic function of the write capability and the message index, and
so is the key derived alongside it. Nothing in the protocol carries a random nonce, so under
ordinary GCM a client that re-derived the same index — after a crash, a restore from backup,
two devices sharing a capability — would repeat a nonce, and GCM's response to that is to leak
the authentication key and with it the ability to forge. SIV's response is to reveal only that
the two plaintexts were equal. That difference is the reason for the mode.

The price is that encryption is a two-pass operation: the tag is computed over the whole
plaintext *before* the keystream that encrypts it exists, because the tag is what seeds the
counter. So `encrypt` cannot stream, which is visible in the interface as `ByteArray` in,
`ByteArray` out.

## Shape of the construction

Three primitives, in a fixed order:

1. **Derive.** Six forward AES calls under the key-generating key turn `(K, nonce)` into a
   16-byte POLYVAL key and a 32-byte message-encryption key. Each call contributes its first
   eight bytes only; the rest is discarded.
2. **Authenticate.** `POLYVAL` over the padded associated data, the padded plaintext and a
   block holding both lengths in bits. The nonce is XORed into the result, the top bit is
   cleared, and one forward AES call under the message-encryption key produces the tag.
3. **Encrypt.** CTR mode seeded with the tag, its top bit set — so the counter can never
   collide with the block that produced the tag — over the plaintext.

Note what the tag covers and what it does not. The lengths are authenticated explicitly, in
the length block, which is what stops an adversary from moving the boundary between associated
data and plaintext. The nonce is authenticated by being folded into the POLYVAL output rather
than hashed with it.
-/

/-- The key-generating key. RFC 8452 also defines a 128-bit variant; BACAP uses this one. -/
abbrev Key := Vector UInt8 32
abbrev Nonce := Vector UInt8 12
abbrev Block := Vector UInt8 16

/-- Little-endian `u32`. -/
private def le32 (i : Nat) : Vector UInt8 4 :=
  Vector.ofFn fun j : Fin 4 => UInt8.ofNat ((i >>> (8 * j.val)) % 256)

/-- Little-endian `u64`. -/
private def le64 (i : Nat) : Vector UInt8 8 :=
  Vector.ofFn fun j : Fin 8 => UInt8.ofNat ((i >>> (8 * j.val)) % 256)

/-- The `i`th derivation block, `LE32(i) ‖ nonce`, and the eight bytes of its encryption that
RFC 8452 keeps. Discarding half of each block is what stops the derived keys from being a
permutation of the key-generating key. -/
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

/-- Zero-pad to a block boundary. Associated data and plaintext are padded *separately* before
being concatenated, which is what keeps the two fields from running into one another. -/
private def pad16 (b : ByteArray) : ByteArray :=
  b ++ ⟨Array.replicate ((16 - b.size % 16) % 16) 0⟩

/-- Fold the nonce into the POLYVAL output and clear the top bit of the last byte. The nonce is
twelve bytes and the block is sixteen, so the last four bytes pass through unchanged. -/
private def maskWithNonce (s : Block) (n : Nonce) : Block :=
  let x : Block := Vector.ofFn fun i : Fin 16 => s[i.val]'i.isLt ^^^ n.toArray.getD i.val 0
  x.set 15 (x[15] &&& 0x7f)

/-- The tag: POLYVAL over `pad(ad) ‖ pad(pt) ‖ LE64(|ad| in bits) ‖ LE64(|pt| in bits)`, masked
with the nonce, then one forward AES call. -/
private def tagOf (key : Key) (n : Nonce) (ad pt : ByteArray) : Block :=
  let lengthBlock := ofVector (le64 (ad.size * 8) ++ le64 (pt.size * 8))
  let s := polyval (authKey key n) (pad16 ad ++ pad16 pt ++ lengthBlock)
  encryptBlockWithKey (encKey key n) (maskWithNonce s n)

/-- The initial counter block: the tag with the top bit of its last byte set. Taking the tag
bytes rather than a `Block` is deliberate — it is what lets `decrypt` seed the counter straight
from the ciphertext it was handed, with no parsing step in between for a proof to reason about.
Bytes past the sixteenth are ignored, and a short input reads as zero-padded. -/
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

/-- XOR a keystream into a buffer. Written as `mapIdx` over the underlying array, rather than a
fold or a loop, so that `ctrXor_ctrXor` below is a two-line proof about one element at a time.
`getD` keeps it total: a keystream shorter than the buffer would XOR with zero rather than
panic, and `size_keystream` rules that case out anyway. -/
private def xorKeystream (ks : ByteArray) (d : ByteArray) : ByteArray :=
  ⟨d.data.mapIdx fun i b => b ^^^ ks.data.getD i 0⟩

/-- CTR mode: the same operation seals and opens, which is the whole reason AES needs no
inverse cipher here. -/
private def ctrXor (ek : Vector UInt8 32) (ctr : Block) (d : ByteArray) : ByteArray :=
  xorKeystream (keystream ek ctr d.size) d

/-! ### CTR mode is its own inverse

The one fact both correctness laws rest on. -/

@[simp] private theorem size_xorKeystream (ks d : ByteArray) :
    (xorKeystream ks d).size = d.size := by
  show (d.data.mapIdx _).size = d.size
  simp

@[simp] private theorem size_ctrXor (ek : Vector UInt8 32) (ctr : Block) (d : ByteArray) :
    (ctrXor ek ctr d).size = d.size := by
  simp [ctrXor]

/-- XORing the same keystream twice is the identity. This — plus the fact that the counter is
seeded from bytes both directions read identically — is all of CTR's correctness. -/
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

/-- Seal: tag first, then encrypt under a counter seeded by the tag, then append the tag. -/
def encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) : ByteArray :=
  let tag := ofVector (tagOf key n ad pt)
  ctrXor (encKey key n) (counterBlock tag) pt ++ tag

/-- Open: split off the tag, decrypt under the counter it seeds, recompute the tag over the
recovered plaintext, and accept only on equality.

The comparison is Lean's structural equality on arrays, which stops at the first differing
byte. A deployed implementation must compare in constant time; nothing in this model does, and
`AES` is not constant time either. -/
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

/-- Opening a well-formed concatenation. Both correctness laws go through this: it is the only
place the tag has to be parsed back out of a ciphertext, and `Util.Bytes` does the work. -/
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

private theorem decrypt_sound (key : Key) (n : Nonce) (ad ct pt : ByteArray)
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

/-- AES-256-GCM-SIV as an `AEAD`. The key stays as raw bytes rather than a precomputed
schedule: every call expands it once for the six derivation blocks and once more for the
message-encryption key, and that expansion is cheap beside the AES calls it feeds. -/
def Scheme : AEAD where
  Key := Key

  name      := "AES-256-GCM-SIV"
  keySize   := 32
  nonceSize := 12
  tagSize   := 16

  -- RFC 8452 §6: beyond 2^36 bytes the security claim lapses. Correctness does not.
  maxPlaintextSize := 2 ^ 36
  maxADSize        := 2 ^ 36

  keyFromBytes := id

  encrypt := encrypt
  decrypt := decrypt

  size_encrypt    := size_encrypt
  decrypt_encrypt := decrypt_encrypt
  decrypt_sound   := decrypt_sound

end CryptWalker.Cipher.AESGCMSIV
