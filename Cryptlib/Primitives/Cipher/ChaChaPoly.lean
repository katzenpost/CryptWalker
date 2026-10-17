/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Cipher.AEAD
import Cryptlib.Primitives.Cipher.ChaCha20
import Cryptlib.Util.Bytes

namespace Cryptlib.Primitives.Cipher.ChaChaPoly

open Cryptlib.Primitives.Cipher.AEAD
open Cryptlib.Util.Bytes

/-! # ChaCha20-Poly1305 (RFC 8439)

The IETF ChaCha20 block (32-bit counter, 96-bit nonce) is the original block with the first
nonce word in the counter's high half, so `ChaCha20.block` serves both. -/

abbrev Key := Vector UInt8 32
abbrev Nonce := Vector UInt8 12

private def leWord (b : Array UInt8) (i : Nat) : UInt32 :=
  b[i]!.toUInt32 ||| (b[i+1]!.toUInt32 <<< 8) ||| (b[i+2]!.toUInt32 <<< 16) ||| (b[i+3]!.toUInt32 <<< 24)

/-- RFC 8439 §2.3: one 64-byte block at a 32-bit counter. -/
def block (key : Key) (n : Nonce) (counter : UInt32) : Array UInt8 :=
  ChaCha20.block key.toArray (n.toArray.extract 4 12) counter (leWord n.toArray 0)

private def keystream (key : Key) (n : Nonce) (len : Nat) : ByteArray :=
  ⟨((List.range ((len + 63) / 64)).foldl
    (fun out i => out ++ block key n (UInt32.ofNat (i + 1))) #[]).extract 0 len⟩

private def xorKeystream (ks d : ByteArray) : ByteArray :=
  -- `ByteArray.data` copies, so convert once rather than per byte
  let k := ks.data
  ⟨d.data.mapIdx fun i b => b ^^^ k.getD i 0⟩

/-- RFC 8439 §2.4: encryption starts at counter 1, block 0 being reserved for the Poly1305 key. -/
def chacha20 (key : Key) (n : Nonce) (d : ByteArray) : ByteArray :=
  xorKeystream (keystream key n d.size) d

/-- RFC 8439 §2.5. Field arithmetic over `Nat` modulo `2^130 - 5`. -/
def poly1305 (otk : Vector UInt8 32) (msg : ByteArray) : Vector UInt8 16 :=
  let le (b : Array UInt8) : Nat := b.foldr (fun x acc => (acc <<< 8) ||| x.toNat) 0
  let r := le (otk.toArray.extract 0 16) &&& 0x0ffffffc0ffffffc0ffffffc0fffffff
  let s := le (otk.toArray.extract 16 32)
  let p := 2 ^ 130 - 5
  -- `ByteArray.data` copies, so convert once rather than per chunk
  let m := msg.data
  let acc := (List.range ((msg.size + 15) / 16)).foldl (fun acc i =>
    let chunk := m.extract (16 * i) (16 * i + 16)
    (acc + le chunk + 2 ^ (8 * chunk.size)) * r % p) 0
  let t := (acc + s) % 2 ^ 128
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat (t >>> (8 * i.val))

private def pad16 (b : ByteArray) : ByteArray :=
  b ++ ⟨Array.replicate ((16 - b.size % 16) % 16) 0⟩

private def le64 (x : Nat) : ByteArray :=
  ⟨Array.ofFn fun i : Fin 8 => UInt8.ofNat (x >>> (8 * i.val))⟩

/-- RFC 8439 §2.8: Poly1305 keyed from block 0, over `pad(ad) ‖ pad(ct) ‖ LE64 |ad| ‖ LE64 |ct|`. -/
def tagOf (key : Key) (n : Nonce) (ad ct : ByteArray) : ByteArray :=
  let otk : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => (block key n 0)[i.val]!
  ofVector (poly1305 otk (pad16 ad ++ pad16 ct ++ le64 ad.size ++ le64 ct.size))

def encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) : ByteArray :=
  let ct := chacha20 key n pt
  ct ++ tagOf key n ad ct

/-- Structural equality on the tag; a deployed implementation must compare in constant time. -/
def decrypt (key : Key) (n : Nonce) (ad ct : ByteArray) : Option ByteArray :=
  if ct.size < 16 then none
  else
    let body := ct.extract 0 (ct.size - 16)
    let tag := ct.extract (ct.size - 16) ct.size
    if (tagOf key n ad body).data = tag.data then some (chacha20 key n body) else none

@[simp] private theorem size_chacha20 (key : Key) (n : Nonce) (d : ByteArray) :
    (chacha20 key n d).size = d.size := by
  show (d.data.mapIdx _).size = d.size
  simp

private theorem chacha20_chacha20 (key : Key) (n : Nonce) (d : ByteArray) :
    chacha20 key n (chacha20 key n d) = d := by
  show xorKeystream (keystream key n (chacha20 key n d).size) (chacha20 key n d) = d
  rw [size_chacha20]
  apply ByteArray.ext
  apply Array.ext
  · simp [xorKeystream, chacha20]
  · intro i h1 h2
    simp only [xorKeystream, chacha20, Array.getElem_mapIdx]
    rw [UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

@[simp] private theorem size_tagOf (key : Key) (n : Nonce) (ad ct : ByteArray) :
    (tagOf key n ad ct).size = 16 := size_ofVector _

private theorem size_encrypt (key : Key) (n : Nonce) (ad pt : ByteArray) :
    (encrypt key n ad pt).size = pt.size + 16 := by
  simp [encrypt, ByteArray.size_append]

private theorem decrypt_append (key : Key) (n : Nonce) (ad body tag : ByteArray)
    (h16 : tag.size = 16) :
    decrypt key n ad (body ++ tag) =
      if (tagOf key n ad body).data = tag.data then some (chacha20 key n body) else none := by
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
  rw [encrypt, decrypt_append _ _ _ _ _ (size_tagOf _ _ _ _), if_pos rfl, chacha20_chacha20]

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
      rw [← Option.some.inj h, encrypt, chacha20_chacha20, ByteArray.ext htag]
      exact hsplit
    · exact absurd h (by simp)

def Scheme : AEAD where
  Key := Key

  name      := "ChaCha20-Poly1305"
  keySize   := 32
  nonceSize := 12
  tagSize   := 16

  maxPlaintextSize := 64 * (2 ^ 32 - 1)
  maxADSize        := 2 ^ 64 - 1

  keyFromBytes := id

  encrypt := encrypt
  decrypt := decrypt

  size_encrypt    := size_encrypt
  decrypt_encrypt := decrypt_encrypt
  decrypt_sound   := decrypt_sound

end Cryptlib.Primitives.Cipher.ChaChaPoly
