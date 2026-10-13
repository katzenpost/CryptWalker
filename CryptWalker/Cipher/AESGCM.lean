/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AEAD
import CryptWalker.Cipher.AES
import CryptWalker.Cipher.GHash
import CryptWalker.Util.Bytes

namespace CryptWalker.Cipher.AESGCM

open CryptWalker.Cipher.AEAD
open CryptWalker.Cipher.AES
open CryptWalker.Cipher.GHash (ghash)
open CryptWalker.Util.Bytes

/-! # AES-256-GCM (NIST SP 800-38D), 96-bit nonces and 128-bit tags

Nonces must not repeat under one key. -/

abbrev Key := Vector UInt8 32
abbrev Nonce := Vector UInt8 12

/-- The counter block `nonce ‖ BE32(i)`; `J₀` is `i = 1` and encryption starts at `i = 2`. -/
private def counterBlock (n : Nonce) (i : Nat) : Vector UInt8 16 :=
  n ++ (Vector.ofFn fun j : Fin 4 => UInt8.ofNat (i >>> (8 * (3 - j.val))) : Vector UInt8 4)

private def keystream (rk : Array UInt8) (n : Nonce) (len : Nat) : ByteArray :=
  ((List.range ((len + 15) / 16)).foldl
    (fun out i => out ++ ofVector (encryptBlock rk (counterBlock n ((i + 2) % 2 ^ 32))))
    ByteArray.empty).extract 0 len

private def xorKeystream (ks d : ByteArray) : ByteArray :=
  -- `ByteArray.data` copies, so convert once rather than per byte
  let k := ks.data
  ⟨d.data.mapIdx fun i b => b ^^^ k.getD i 0⟩

def gctr (key : Key) (n : Nonce) (d : ByteArray) : ByteArray :=
  xorKeystream (keystream (expandKey key) n d.size) d

private def pad16 (b : ByteArray) : ByteArray :=
  b ++ ⟨Array.replicate ((16 - b.size % 16) % 16) 0⟩

private def be64 (x : Nat) : ByteArray :=
  ⟨Array.ofFn fun i : Fin 8 => UInt8.ofNat (x >>> (8 * (7 - i.val)))⟩

/-- `E(K, J₀) ⊕ GHASH_H(pad(A) ‖ pad(C) ‖ BE64(|A| bits) ‖ BE64(|C| bits))`, `H = E(K, 0¹²⁸)`. -/
def tagOf (key : Key) (n : Nonce) (ad ct : ByteArray) : ByteArray :=
  let rk := expandKey key
  let h := encryptBlock rk (Vector.replicate 16 0)
  let s := ghash h (pad16 ad ++ pad16 ct ++ be64 (8 * ad.size) ++ be64 (8 * ct.size))
  let ej := encryptBlock rk (counterBlock n 1)
  ofVector (Vector.ofFn fun i : Fin 16 => s[i] ^^^ ej[i])

def encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) : ByteArray :=
  let ct := gctr key n pt
  ct ++ tagOf key n ad ct

/-- Structural equality on the tag; a deployed implementation must compare in constant time. -/
def decrypt (key : Key) (n : Nonce) (ad ct : ByteArray) : Option ByteArray :=
  if ct.size < 16 then none
  else
    let body := ct.extract 0 (ct.size - 16)
    let tag := ct.extract (ct.size - 16) ct.size
    if (tagOf key n ad body).data = tag.data then some (gctr key n body) else none

@[simp] private theorem size_gctr (key : Key) (n : Nonce) (d : ByteArray) :
    (gctr key n d).size = d.size := by
  show (d.data.mapIdx _).size = d.size
  simp

private theorem gctr_gctr (key : Key) (n : Nonce) (d : ByteArray) :
    gctr key n (gctr key n d) = d := by
  show xorKeystream (keystream (expandKey key) n (gctr key n d).size) (gctr key n d) = d
  rw [size_gctr]
  apply ByteArray.ext
  apply Array.ext
  · simp [xorKeystream, gctr]
  · intro i h1 h2
    simp only [xorKeystream, gctr, Array.getElem_mapIdx]
    rw [UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

@[simp] private theorem size_tagOf (key : Key) (n : Nonce) (ad ct : ByteArray) :
    (tagOf key n ad ct).size = 16 := size_ofVector _

private theorem size_encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) :
    (encrypt key n ad pt).size = pt.size + 16 := by
  simp [encrypt, ByteArray.size_append]

private theorem decrypt_append (key : Key) (n : Nonce) (ad body tag : ByteArray)
    (h16 : tag.size = 16) :
    decrypt key n ad (body ++ tag) =
      if (tagOf key n ad body).data = tag.data then some (gctr key n body) else none := by
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
  rw [encrypt, decrypt_append _ _ _ _ _ (size_tagOf _ _ _ _), if_pos rfl, gctr_gctr]

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
      rw [← Option.some.inj h, encrypt, gctr_gctr, ByteArray.ext htag]
      exact hsplit
    · exact absurd h (by simp)

def Scheme : AEAD where
  Key := Key

  name      := "AES-256-GCM"
  keySize   := 32
  nonceSize := 12
  tagSize   := 16

  -- SP 800-38D §5.2.1.1: plaintext at most 2^39 - 256 bits, AD at most 2^64 - 1 bits.
  maxPlaintextSize := (2 ^ 39 - 256) / 8
  maxADSize        := (2 ^ 64 - 1) / 8

  keyFromBytes := id

  encrypt := encrypt
  decrypt := decrypt

  size_encrypt    := size_encrypt
  decrypt_encrypt := decrypt_encrypt
  decrypt_sound   := decrypt_sound

end CryptWalker.Cipher.AESGCM
