/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.CborProofs
import CryptWalker.GroupChat.Member.Gcm

/-! # A message reads back as written

`decode_encode`: every message this client writes, read back, is the message it wrote. -/

namespace CryptWalker.GroupChat.Member.Gcm

open Cbor

/-- A field this client writes and reads back. -/
def FieldWF : Field → Prop
  | .version n => n < 2 ^ 64
  | .hash b => b.size < 2 ^ 64
  | .msgType n => n < 2 ^ 64
  | .text s => s.utf8ByteSize < 2 ^ 64
  | .intro i => 1 ≤ i.name.length ∧ i.name.length ≤ maxNameChars ∧ i.readCap.size = readCapSize
      ∧ i.name.utf8ByteSize < 2 ^ 64
  | .other _ _ => False
  | .acks b | .numbers b | .introducedAt b => b.size < 2 ^ 64

theorem bytes_size (b : ByteArray) : b.data.toList.length = b.size := Array.length_toList

theorem readByteArray_bytes (b : ByteArray) (rest : List UInt8) (hb : b.size < 2 ^ 64) :
    readByteArray (bytes b.data.toList ++ rest) = some (b, rest) := by
  unfold readByteArray
  rw [readBytes_bytes _ _ (by rw [bytes_size]; exact hb)]
  rfl

theorem nullable_some {α : Type} (read : List UInt8 → Option (α × List UInt8)) (l : List UInt8)
    (a : α) (rest : List UInt8) (h : read l = some (a, rest)) (hn : isNull l = false) :
    nullable read l = some (some a, rest) := by
  simp [nullable, hn, h]

theorem isNull_cons (x : ℕ) (r : List UInt8) (hx : x < 246) : isNull (x.toUInt8 :: r) = false := by
  simp only [isNull, List.head?_cons]
  cases h : (some x.toUInt8 == some (0xf6 : UInt8))
  · rfl
  · have := congrArg UInt8.toNat (Option.some.inj (beq_iff_eq.1 h))
    simp at this
    omega

theorem isNull_header (m n : ℕ) (rest : List UInt8) (hm : m < 7) :
    isNull (header m n ++ rest) = false := by
  unfold header
  split_ifs <;> simp only [List.cons_append] <;> exact isNull_cons _ _ (by omega)

theorem byteArray_eta (b : ByteArray) : (⟨b.data.toList.toArray⟩ : ByteArray) = b := by simp

theorem readIntro_encodeIntro (i : Introduction) (rest : List UInt8)
    (hn : 1 ≤ i.name.length ∧ i.name.length ≤ maxNameChars ∧ i.readCap.size = readCapSize
      ∧ i.name.utf8ByteSize < 2 ^ 64) :
    readIntro (encodeIntro i ++ rest) = some (i, rest) := by
  obtain ⟨h1, h2, h3, h4⟩ := hn
  have hcap : i.readCap.data.toList.length < 2 ^ 64 := by
    rw [bytes_size, h3]; decide
  simp only [encodeIntro, List.append_assoc, readIntro, readHeader_header 5 2 _ (by omega) (by omega),
    Option.bind_eq_bind, Option.bind_some, ne_eq, not_true_eq_false, if_false]
  rw [show introEntries 2 = introEntries (0 + 1 + 1) from rfl]
  simp only [introEntries, readText_text "display_name" _ (by decide), Option.bind_eq_bind,
    Option.bind_some, if_true]
  simp only [readText_text i.name _ h4, Option.bind_some,
    readText_text "read_cap" _ (by decide)]
  simp [readBytes_bytes _ _ hcap, h1, h2, h3]

theorem readField_encodeField (f : Field) (hf : FieldWF f) (rest : List UInt8) :
    readField (encodeField f ++ rest) = some (some f, rest) := by
  cases f with
  | version n =>
    simp only [encodeField, List.append_assoc, readField, readText_text "version" _ (by decide)]
    simp [readUInt_uint n rest hf]
  | hash b =>
    simp only [encodeField, List.append_assoc, readField,
      readText_text "membership_hash" _ (by decide)]
    simp [readByteArray_bytes b rest hf]
  | msgType n =>
    simp only [encodeField, List.append_assoc, readField, readText_text "msg_type" _ (by decide)]
    simp [nullable_some _ _ n rest (readUInt_uint n rest hf) (isNull_header 0 n rest (by omega))]
  | text t =>
    simp only [encodeField, List.append_assoc, readField, readText_text "text" _ (by decide)]
    simp [nullable_some _ _ t rest (readText_text t rest hf)
      (by unfold Cbor.text; rw [List.append_assoc]; exact isNull_header 3 _ _ (by omega))]
  | intro i =>
    simp only [encodeField, List.append_assoc, readField,
      readText_text "introduction" _ (by decide)]
    simp [nullable_some _ _ i rest (readIntro_encodeIntro i rest hf)
      (by unfold encodeIntro; simp only [List.append_assoc]; exact isNull_header 5 _ _ (by omega))]
  | other k raw => exact absurd hf id
  | acks b =>
    simp only [encodeField, List.append_assoc, readField, readText_text "acks" _ (by decide)]
    simp [otherKeys, nullable_some _ _ b rest (readByteArray_bytes b rest hf)
      (by unfold bytes; rw [List.append_assoc]; exact isNull_header 2 _ _ (by omega))]
  | numbers b =>
    simp only [encodeField, List.append_assoc, readField, readText_text "numbers" _ (by decide)]
    simp [otherKeys, nullable_some _ _ b rest (readByteArray_bytes b rest hf)
      (by unfold bytes; rw [List.append_assoc]; exact isNull_header 2 _ _ (by omega))]
  | introducedAt b =>
    simp only [encodeField, List.append_assoc, readField,
      readText_text "introduced_at" _ (by decide)]
    simp [otherKeys, nullable_some _ _ b rest (readByteArray_bytes b rest hf)
      (by unfold bytes; rw [List.append_assoc]; exact isNull_header 2 _ _ (by omega))]

theorem readFields_flatMap : ∀ (fs : List Field) (acc : Acc) (rest : List UInt8),
    (∀ f ∈ fs, FieldWF f) →
    readFields fs.length acc (fs.flatMap encodeField ++ rest) = some (fs.foldl Acc.add acc, rest)
  | [], _, _, _ => rfl
  | f :: fs, acc, rest, h => by
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, readFields,
      readField_encodeField f (h f List.mem_cons_self) _, Option.bind_eq_bind, Option.bind_some,
      List.foldl_cons]
    exact readFields_flatMap fs _ rest fun g hg => h g (List.mem_cons_of_mem _ hg)

/-- A message this client writes and reads back as it was. -/
structure WF (g : Gcm) : Prop where
  version : g.version ≤ currentVersion
  hash : g.membershipHash.size = hashSize
  msgType : g.msgType ≤ MsgType.control
  text : ∀ s ∈ g.text, s.utf8ByteSize < 2 ^ 64
  intro : ∀ i ∈ g.introduction, 1 ≤ i.name.length ∧ i.name.length ≤ maxNameChars
    ∧ i.readCap.size = readCapSize ∧ i.name.utf8ByteSize < 2 ^ 64
  other : g.other = []
  acks : ∀ b ∈ g.acks, b.size < 2 ^ 64
  numbers : ∀ b ∈ g.numbers, b.size < 2 ^ 64
  introducedAt : ∀ b ∈ g.introducedAt, b.size < 2 ^ 64

theorem fields_wf {g : Gcm} (h : WF g) : ∀ f ∈ fields g, FieldWF f := by
  obtain ⟨hv, hh, ht, htext, hintro, hother, hacks, hnum, hia⟩ := h
  simp only [currentVersion, hashSize, MsgType.control] at hv hh ht
  simp only [fields, hother, List.map_nil, List.append_nil, List.forall_mem_append,
    List.forall_mem_cons, List.not_mem_nil, List.forall_mem_map, Option.mem_toList, FieldWF,
    IsEmpty.forall_iff, implies_true, and_true]
  and_intros
  all_goals omega

theorem finish_fields {g : Gcm} (h : WF g) : ((fields g).foldl Acc.add {}).finish = some g := by
  obtain ⟨v, hs, t, text, intro, other, acks, numbers, ia⟩ := g
  obtain ⟨hv, hh, ht, -, -, rfl, -, -, -⟩ := h
  dsimp only at hv hh ht
  simp only [currentVersion, hashSize, MsgType.control] at hv hh ht
  have hv' : ¬ 3 < v := by omega
  have ht' : ¬ 10 < t := by omega
  cases text <;> cases intro <;> cases acks <;> cases numbers <;> cases ia <;>
    simp [fields, Acc.add, Acc.finish, hv', hh, ht', currentVersion, hashSize,
      MsgType.control]

/-- Decoding undoes encoding. -/
theorem decode_encode {g : Gcm} (h : WF g) : decode (encode g) = some g := by
  have hlen : (fields g).length < 2 ^ 64 := by
    have : (fields g).length ≤ 8 := by
      obtain ⟨_, _, _, text, intro, other, acks, numbers, ia⟩ := g
      have := h.other; simp only at this; subst this
      cases text <;> cases intro <;> cases acks <;> cases numbers <;> cases ia <;> simp [fields]
    omega
  have hread := readFields_flatMap (fields g) {} [] (fields_wf h)
  simp only [List.append_nil] at hread
  simp only [decode, encode, decodeList, encodeList, List.toList_toArray,
    readHeader_header 5 _ _ (by omega) hlen, Option.bind_eq_bind, Option.bind_some, ne_eq,
    not_true_eq_false, if_false, hread]
  exact finish_fields h

end CryptWalker.GroupChat.Member.Gcm
