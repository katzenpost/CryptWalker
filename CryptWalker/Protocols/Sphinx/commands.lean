/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic.Set
import Mathlib.Tactic.IntervalCases
import CryptWalker.Protocols.Sphinx.constants
import CryptWalker.Util.Bytes

namespace CryptWalker.Protocols.Sphinx.Commands

open CryptWalker.Protocols.Sphinx.Constants
open CryptWalker.Util.Bytes (ofVector size_ofVector extract_append_left extract_append_right
  extract_append_of_le extract_append_ge append_extract)

/-! # Sphinx per-hop routing commands

A routing-info block is a sequence of tag-prefixed commands, read until a `null` tag or the end of
the block. Every command has a constant wire size. -/

/-- A routing command. `null` is the terminal marker (tag `0x00`, no body). -/
inductive RoutingCommand where
  | nextNodeHop (id : Vector UInt8 32) (mac : Vector UInt8 32)
  | recipient (id : Vector UInt8 32)
  | surbReply (id : Vector UInt8 16)
  | nodeDelay (delay : UInt32)
  | null
  deriving BEq, Repr

private def u32be (n : UInt32) : Vector UInt8 4 :=
  Vector.ofFn fun i : Fin 4 => (n >>> (8 * UInt32.ofNat (3 - i.val))).toUInt8

private def u32ofBE (b0 b1 b2 b3 : UInt8) : UInt32 :=
  (b0.toUInt32 <<< 24) ||| (b1.toUInt32 <<< 16) ||| (b2.toUInt32 <<< 8) ||| b3.toUInt32

def RoutingCommand.toBytes : RoutingCommand → ByteArray
  | .nextNodeHop id mac => ⟨#[0x01]⟩ ++ ofVector id ++ ofVector mac
  | .recipient id       => ⟨#[0x02]⟩ ++ ofVector id
  | .surbReply id       => ⟨#[0x03]⟩ ++ ofVector id
  | .nodeDelay d        => ⟨#[0x80]⟩ ++ ofVector (u32be d)
  | .null               => ⟨#[0x00]⟩

/-- A `.nextNodeHop` serializes to exactly `nextNodeHopLength` bytes. -/
@[simp] theorem RoutingCommand.nextNodeHop_toBytes_size (id mac : Vector UInt8 32) :
    (RoutingCommand.nextNodeHop id mac).toBytes.size = nextNodeHopLength := by
  simp only [RoutingCommand.toBytes, ByteArray.size_append, CryptWalker.Util.Bytes.size_ofVector,
    nextNodeHopLength, commandTagLength, nodeIDLength, macLength]
  rfl

/-- Parse one command, returning it and the unconsumed remainder. `none` means an empty buffer or
the `null` terminal. -/
def fromBytesOne (b : ByteArray) : Except String (Option RoutingCommand × ByteArray) := do
  if b.size == 0 then
    pure (none, b)
  else if b.size == 1 then
    if b.get! 0 == 0x00 then pure (none, ByteArray.empty)
    else throw "sphinx: invalid per-hop command"
  else
    let id := b.get! 0
    let rest0 := b.extract 1 b.size
    match id with
    | 0x00 =>
      -- Terminal: any trailing bytes must be the zero padding of a fixed-size block.
      if rest0.data.all (· == 0) then pure (none, ByteArray.empty)
      else throw "sphinx: invalid per-hop command"
    | 0x01 =>
      if rest0.size < nextNodeHopLength - 1 then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! i.val
        let macV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! (32 + i.val)
        pure (some (.nextNodeHop idV macV), rest0.extract (nextNodeHopLength - 1) rest0.size)
    | 0x02 =>
      if rest0.size < recipientIDLength then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! i.val
        pure (some (.recipient idV), rest0.extract recipientIDLength rest0.size)
    | 0x03 =>
      if rest0.size < surbIDLength then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 16 := Vector.ofFn fun i : Fin 16 => rest0.get! i.val
        pure (some (.surbReply idV), rest0.extract surbIDLength rest0.size)
    | 0x80 =>
      if rest0.size < 4 then throw "sphinx: invalid per-hop command"
      else
        let d := u32ofBE (rest0.get! 0) (rest0.get! 1) (rest0.get! 2) (rest0.get! 3)
        pure (some (.nodeDelay d), rest0.extract 4 rest0.size)
    | _ => throw "sphinx: invalid per-hop command"

/-- `parseAll` with explicit fuel, so its behavior is provable. -/
def parseAllFuel : Nat → ByteArray → Except String (List RoutingCommand)
  | 0, _ => pure []
  | fuel + 1, b => do
    match ← fromBytesOne b with
    | (none, _)        => pure []
    | (some cmd, rest) => pure (cmd :: (← parseAllFuel fuel rest))

/-- Parse every command in a routing-info block, stopping at `null` or the end of the buffer. -/
def parseAll (b : ByteArray) : Except String (List RoutingCommand) := parseAllFuel b.size b

/-! ## `parseAll` undoes `commandsToBytes` -/

private theorem byteArray_get!_eq (b : ByteArray) (i : Nat) : b.get! i = b[i]! := by
  show b.data[i]! = b[i]!
  by_cases h : i < b.size
  · rw [getElem!_pos b i h]
    show b.data[i]! = b.get i h
    rw [getElem!_pos b.data i h]
    rfl
  · rw [getElem!_neg b i h]
    show b.data[i]! = (default : UInt8)
    exact getElem!_neg b.data i (by simpa using h)

private theorem get!_append_left (a b : ByteArray) {i : Nat} (h : i < a.size) :
    (a ++ b).get! i = a.get! i := by
  have h2 : i < (a ++ b).size := by rw [ByteArray.size_append]; omega
  rw [byteArray_get!_eq (a ++ b) i, byteArray_get!_eq a i, getElem!_pos (a ++ b) i h2,
    getElem!_pos a i h, ByteArray.getElem_append_left h]

private theorem get!_append_right (a b : ByteArray) (k : Nat) (hk : k < b.size) :
    (a ++ b).get! (a.size + k) = b.get! k := by
  have h2 : a.size + k < (a ++ b).size := by rw [ByteArray.size_append]; omega
  have h3 : a.size ≤ a.size + k := Nat.le_add_right _ _
  rw [byteArray_get!_eq (a ++ b) (a.size + k), byteArray_get!_eq b k,
    getElem!_pos (a ++ b) (a.size + k) h2, getElem!_pos b k hk,
    ByteArray.getElem_append_right h3]
  congr 1
  omega

private theorem get!_ofVector {n : Nat} (v : Vector UInt8 n) (i : Nat) (hi : i < n) :
    (ofVector v).get! i = v[i] := by
  show v.toArray[i]! = v[i]
  simp [getElem!_pos, hi]

private theorem get!_extract_from (b : ByteArray) (lo j : Nat)
    (hj : j < (b.extract lo b.size).size) :
    (b.extract lo b.size).get! j = b.get! (lo + j) := by
  have h2 : lo + j < b.size := by rw [ByteArray.size_extract] at hj; omega
  rw [byteArray_get!_eq (b.extract lo b.size) j, byteArray_get!_eq b (lo + j),
    getElem!_pos (b.extract lo b.size) j hj, getElem!_pos b (lo + j) h2,
    ByteArray.getElem_extract]


private theorem byteArray_ext_get! {a b : ByteArray} (hsize : a.size = b.size)
    (h : ∀ i, i < a.size → a.get! i = b.get! i) : a = b := by
  apply ByteArray.ext_getElem hsize
  intro i hi hi'
  have := h i hi
  rwa [byteArray_get!_eq a i, byteArray_get!_eq b i, getElem!_pos a i hi, getElem!_pos b i hi'] at this

set_option maxHeartbeats 4000000 in
private theorem fromBytesOne_toBytes_append_nextNodeHop (id mac : Vector UInt8 32) (rest : ByteArray) :
    fromBytesOne ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest) =
      .ok (some (.nextNodeHop id mac), rest) := by
  set A1 : ByteArray := ⟨#[0x01]⟩ with hA1
  set A2 : ByteArray := A1 ++ ofVector id with hA2
  set A3 : ByteArray := A2 ++ ofVector mac with hA3
  have hA1sz : A1.size = 1 := rfl
  have hA2sz : A2.size = 33 := by rw [hA2, ByteArray.size_append, hA1sz, size_ofVector]
  have hA3sz : A3.size = 65 := by rw [hA3, ByteArray.size_append, hA2sz, size_ofVector]
  have hcmd : (RoutingCommand.nextNodeHop id mac).toBytes = A3 := by
    rw [hA3, hA2, hA1]; rfl
  have hbsz : ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size = 65 + rest.size := by
    rw [hcmd, ByteArray.size_append, hA3sz]
  have h0 : (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size == 0) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have h1 : (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size == 1) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have htag : ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).get! 0 = 0x01 := by
    rw [hcmd, get!_append_left A3 rest (by omega), hA3,
      get!_append_left A2 (ofVector mac) (by omega), hA2,
      get!_append_left A1 (ofVector id) (by omega)]
    rfl
  have hrest0sz : (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
      ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).size = 64 + rest.size := by
    rw [ByteArray.size_extract, hbsz]; omega
  have hnnh : nextNodeHopLength - 1 = 64 := by simp [nextNodeHopLength, commandTagLength, nodeIDLength, macLength]
  have hle : ¬ ((((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
      ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).size < nextNodeHopLength - 1) := by
    rw [hnnh, hrest0sz]; omega
  have hidV : (Vector.ofFn fun i : Fin 32 =>
      (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
        ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).get! i.val) = id := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn,
      get!_extract_from _ 1 i (by rw [hrest0sz]; omega),
      hcmd, get!_append_left A3 rest (by rw [hA3sz]; omega),
      hA3, get!_append_left A2 (ofVector mac) (by rw [hA2sz]; omega),
      hA2, show (1 + i) = A1.size + i from by rw [hA1sz],
      get!_append_right A1 (ofVector id) i (by simpa using hi),
      get!_ofVector id i hi]
  have hmacV : (Vector.ofFn fun i : Fin 32 =>
      (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
        ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).get! (32 + i.val)) = mac := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn,
      get!_extract_from _ 1 (32 + i) (by rw [hrest0sz]; omega),
      show (1 + (32 + i)) = 33 + i from by omega,
      hcmd, get!_append_left A3 rest (by rw [hA3sz]; omega),
      hA3, show (33 + i) = A2.size + i from by rw [hA2sz],
      get!_append_right A2 (ofVector mac) i (by simpa using hi),
      get!_ofVector mac i hi]
  have hrestTail : (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
      ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).extract (nextNodeHopLength - 1)
      (((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
        ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).size = rest := by
    rw [hnnh]
    have hsz2 : ((((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
        ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).extract 64
        ((((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).extract 1
          ((RoutingCommand.nextNodeHop id mac).toBytes ++ rest).size).size)).size = rest.size := by
      rw [ByteArray.size_extract, hrest0sz]; omega
    apply byteArray_ext_get!
    · exact hsz2
    · intro k hk
      have hkr : k < rest.size := by rw [← hsz2]; exact hk
      rw [get!_extract_from _ 64 k hk,
        get!_extract_from _ 1 (64 + k) (by rw [hrest0sz]; omega),
        show (1 + (64 + k)) = A3.size + k from by rw [hA3sz]; omega,
        hcmd, get!_append_right A3 rest k hkr]
  -- Generalize the expression before unfolding `fromBytesOne`, or elaboration times out.
  revert h0 h1 htag hle hidV hmacV hrestTail
  generalize (RoutingCommand.nextNodeHop id mac).toBytes ++ rest = b
  intro h0 h1 htag hle hidV hmacV hrestTail
  unfold fromBytesOne
  simp only [h0, h1, Bool.false_eq_true, if_false, htag, hle, hidV, hmacV, hrestTail, pure,
    Except.pure]

set_option maxHeartbeats 4000000 in
private theorem fromBytesOne_toBytes_append_recipient (id : Vector UInt8 32) (rest : ByteArray) :
    fromBytesOne ((RoutingCommand.recipient id).toBytes ++ rest) =
      .ok (some (.recipient id), rest) := by
  set A1 : ByteArray := ⟨#[0x02]⟩ with hA1
  set A2 : ByteArray := A1 ++ ofVector id with hA2
  have hA1sz : A1.size = 1 := rfl
  have hA2sz : A2.size = 33 := by rw [hA2, ByteArray.size_append, hA1sz, size_ofVector]
  have hcmd : (RoutingCommand.recipient id).toBytes = A2 := by rw [hA2, hA1]; rfl
  have hbsz : ((RoutingCommand.recipient id).toBytes ++ rest).size = 33 + rest.size := by
    rw [hcmd, ByteArray.size_append, hA2sz]
  have h0 : (((RoutingCommand.recipient id).toBytes ++ rest).size == 0) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have h1 : (((RoutingCommand.recipient id).toBytes ++ rest).size == 1) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have htag : ((RoutingCommand.recipient id).toBytes ++ rest).get! 0 = 0x02 := by
    rw [hcmd, get!_append_left A2 rest (by omega), hA2,
      get!_append_left A1 (ofVector id) (by omega)]
    rfl
  have hrest0sz : (((RoutingCommand.recipient id).toBytes ++ rest).extract 1
      ((RoutingCommand.recipient id).toBytes ++ rest).size).size = 32 + rest.size := by
    rw [ByteArray.size_extract, hbsz]; omega
  have hle : ¬ ((((RoutingCommand.recipient id).toBytes ++ rest).extract 1
      ((RoutingCommand.recipient id).toBytes ++ rest).size).size < recipientIDLength) := by
    simp only [recipientIDLength, hrest0sz]; omega
  have hidV : (Vector.ofFn fun i : Fin 32 =>
      (((RoutingCommand.recipient id).toBytes ++ rest).extract 1
        ((RoutingCommand.recipient id).toBytes ++ rest).size).get! i.val) = id := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn,
      get!_extract_from _ 1 i (by rw [hrest0sz]; omega),
      hcmd, get!_append_left A2 rest (by rw [hA2sz]; omega),
      hA2, show (1 + i) = A1.size + i from by rw [hA1sz],
      get!_append_right A1 (ofVector id) i (by simpa using hi),
      get!_ofVector id i hi]
  have hrestTail : (((RoutingCommand.recipient id).toBytes ++ rest).extract 1
      ((RoutingCommand.recipient id).toBytes ++ rest).size).extract recipientIDLength
      (((RoutingCommand.recipient id).toBytes ++ rest).extract 1
        ((RoutingCommand.recipient id).toBytes ++ rest).size).size = rest := by
    simp only [recipientIDLength]
    have hsz2 : ((((RoutingCommand.recipient id).toBytes ++ rest).extract 1
        ((RoutingCommand.recipient id).toBytes ++ rest).size).extract 32
        ((((RoutingCommand.recipient id).toBytes ++ rest).extract 1
          ((RoutingCommand.recipient id).toBytes ++ rest).size).size)).size = rest.size := by
      rw [ByteArray.size_extract, hrest0sz]; omega
    apply byteArray_ext_get!
    · exact hsz2
    · intro k hk
      have hkr : k < rest.size := by rw [← hsz2]; exact hk
      rw [get!_extract_from _ 32 k hk,
        get!_extract_from _ 1 (32 + k) (by rw [hrest0sz]; omega),
        show (1 + (32 + k)) = A2.size + k from by rw [hA2sz]; omega,
        hcmd, get!_append_right A2 rest k hkr]
  revert h0 h1 htag hle hidV hrestTail
  generalize (RoutingCommand.recipient id).toBytes ++ rest = b
  intro h0 h1 htag hle hidV hrestTail
  unfold fromBytesOne
  simp only [h0, h1, Bool.false_eq_true, if_false, htag, hle, hidV, hrestTail, pure, Except.pure]

set_option maxHeartbeats 4000000 in
private theorem fromBytesOne_toBytes_append_surbReply (id : Vector UInt8 16) (rest : ByteArray) :
    fromBytesOne ((RoutingCommand.surbReply id).toBytes ++ rest) =
      .ok (some (.surbReply id), rest) := by
  set A1 : ByteArray := ⟨#[0x03]⟩ with hA1
  set A2 : ByteArray := A1 ++ ofVector id with hA2
  have hA1sz : A1.size = 1 := rfl
  have hA2sz : A2.size = 17 := by rw [hA2, ByteArray.size_append, hA1sz, size_ofVector]
  have hcmd : (RoutingCommand.surbReply id).toBytes = A2 := by rw [hA2, hA1]; rfl
  have hbsz : ((RoutingCommand.surbReply id).toBytes ++ rest).size = 17 + rest.size := by
    rw [hcmd, ByteArray.size_append, hA2sz]
  have h0 : (((RoutingCommand.surbReply id).toBytes ++ rest).size == 0) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have h1 : (((RoutingCommand.surbReply id).toBytes ++ rest).size == 1) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have htag : ((RoutingCommand.surbReply id).toBytes ++ rest).get! 0 = 0x03 := by
    rw [hcmd, get!_append_left A2 rest (by omega), hA2,
      get!_append_left A1 (ofVector id) (by omega)]
    rfl
  have hrest0sz : (((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
      ((RoutingCommand.surbReply id).toBytes ++ rest).size).size = 16 + rest.size := by
    rw [ByteArray.size_extract, hbsz]; omega
  have hle : ¬ ((((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
      ((RoutingCommand.surbReply id).toBytes ++ rest).size).size < surbIDLength) := by
    simp only [surbIDLength, hrest0sz]; omega
  have hidV : (Vector.ofFn fun i : Fin 16 =>
      (((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
        ((RoutingCommand.surbReply id).toBytes ++ rest).size).get! i.val) = id := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn,
      get!_extract_from _ 1 i (by rw [hrest0sz]; omega),
      hcmd, get!_append_left A2 rest (by rw [hA2sz]; omega),
      hA2, show (1 + i) = A1.size + i from by rw [hA1sz],
      get!_append_right A1 (ofVector id) i (by simpa using hi),
      get!_ofVector id i hi]
  have hrestTail : (((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
      ((RoutingCommand.surbReply id).toBytes ++ rest).size).extract surbIDLength
      (((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
        ((RoutingCommand.surbReply id).toBytes ++ rest).size).size = rest := by
    simp only [surbIDLength]
    have hsz2 : ((((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
        ((RoutingCommand.surbReply id).toBytes ++ rest).size).extract 16
        ((((RoutingCommand.surbReply id).toBytes ++ rest).extract 1
          ((RoutingCommand.surbReply id).toBytes ++ rest).size).size)).size = rest.size := by
      rw [ByteArray.size_extract, hrest0sz]; omega
    apply byteArray_ext_get!
    · exact hsz2
    · intro k hk
      have hkr : k < rest.size := by rw [← hsz2]; exact hk
      rw [get!_extract_from _ 16 k hk,
        get!_extract_from _ 1 (16 + k) (by rw [hrest0sz]; omega),
        show (1 + (16 + k)) = A2.size + k from by rw [hA2sz]; omega,
        hcmd, get!_append_right A2 rest k hkr]
  revert h0 h1 htag hle hidV hrestTail
  generalize (RoutingCommand.surbReply id).toBytes ++ rest = b
  intro h0 h1 htag hle hidV hrestTail
  unfold fromBytesOne
  simp only [h0, h1, Bool.false_eq_true, if_false, htag, hle, hidV, hrestTail, pure, Except.pure]

/-- `u32ofBE` undoes `u32be`. -/
private theorem u32ofBE_u32be (d : UInt32) :
    u32ofBE (u32be d)[0] (u32be d)[1] (u32be d)[2] (u32be d)[3] = d := by
  have h0 : (u32be d)[0] = (d >>> 24).toUInt8 := by unfold u32be; simp
  have h1 : (u32be d)[1] = (d >>> 16).toUInt8 := by unfold u32be; simp
  have h2 : (u32be d)[2] = (d >>> 8).toUInt8 := by unfold u32be; simp
  have h3 : (u32be d)[3] = (d >>> 0).toUInt8 := by unfold u32be; simp
  rw [h0, h1, h2, h3]
  unfold u32ofBE
  apply UInt32.toBitVec_inj.mp
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have e24 : (UInt32.toBitVec (24 : UInt32)).toNat = 24 := by decide
  have e16 : (UInt32.toBitVec (16 : UInt32)).toNat = 16 := by decide
  have e8 : (UInt32.toBitVec (8 : UInt32)).toNat = 8 := by decide
  have m24 : (UInt32.toBitVec (24 : UInt32)) % 32 = UInt32.toBitVec 24 := by decide
  have m16 : (UInt32.toBitVec (16 : UInt32)) % 32 = UInt32.toBitVec 16 := by decide
  have m8 : (UInt32.toBitVec (8 : UInt32)) % 32 = UInt32.toBitVec 8 := by decide
  have m0 : (UInt32.toBitVec (0 : UInt32)) % 32 = UInt32.toBitVec 0 := by decide
  simp only [UInt32.toBitVec_or, UInt32.toBitVec_shiftLeft, UInt32.toBitVec_toUInt8,
    UInt32.toBitVec_shiftRight, UInt8.toBitVec_toUInt32, BitVec.getLsbD_or,
    BitVec.getLsbD_setWidth, BitVec.shiftLeft_eq', BitVec.getLsbD_shiftLeft,
    e24, e16, e8, m24, m16, m8, m0, BitVec.ushiftRight_eq', BitVec.getLsbD_ushiftRight, hi]
  interval_cases i <;> simp

set_option maxHeartbeats 4000000 in
private theorem fromBytesOne_toBytes_append_nodeDelay (d : UInt32) (rest : ByteArray) :
    fromBytesOne ((RoutingCommand.nodeDelay d).toBytes ++ rest) =
      .ok (some (.nodeDelay d), rest) := by
  set A1 : ByteArray := ⟨#[0x80]⟩ with hA1
  set A2 : ByteArray := A1 ++ ofVector (u32be d) with hA2
  have hA1sz : A1.size = 1 := rfl
  have hA2sz : A2.size = 5 := by rw [hA2, ByteArray.size_append, hA1sz, size_ofVector]
  have hcmd : (RoutingCommand.nodeDelay d).toBytes = A2 := by rw [hA2, hA1]; rfl
  have hbsz : ((RoutingCommand.nodeDelay d).toBytes ++ rest).size = 5 + rest.size := by
    rw [hcmd, ByteArray.size_append, hA2sz]
  have h0 : (((RoutingCommand.nodeDelay d).toBytes ++ rest).size == 0) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have h1 : (((RoutingCommand.nodeDelay d).toBytes ++ rest).size == 1) = false := by
    rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
  have htag : ((RoutingCommand.nodeDelay d).toBytes ++ rest).get! 0 = 0x80 := by
    rw [hcmd, get!_append_left A2 rest (by omega), hA2,
      get!_append_left A1 (ofVector (u32be d)) (by omega)]
    rfl
  have hrest0sz : (((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
      ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).size = 4 + rest.size := by
    rw [ByteArray.size_extract, hbsz]; omega
  have hle : ¬ ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
      ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).size < 4) := by
    rw [hrest0sz]; omega
  have hbyte : ∀ j : Nat, j < 4 → (((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
      ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).get! j
      = (ofVector (u32be d)).get! j := by
    intro j hj
    rw [get!_extract_from _ 1 j (by rw [hrest0sz]; omega),
      hcmd, get!_append_left A2 rest (by rw [hA2sz]; omega),
      hA2, show (1 + j) = A1.size + j from by rw [hA1sz],
      get!_append_right A1 (ofVector (u32be d)) j hj]
  have hd : u32ofBE
      ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).get! 0)
      ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).get! 1)
      ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).get! 2)
      ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).get! 3) = d := by
    rw [hbyte 0 (by omega), hbyte 1 (by omega), hbyte 2 (by omega), hbyte 3 (by omega),
      get!_ofVector (u32be d) 0 (by omega), get!_ofVector (u32be d) 1 (by omega),
      get!_ofVector (u32be d) 2 (by omega), get!_ofVector (u32be d) 3 (by omega)]
    exact u32ofBE_u32be d
  have hrestTail : (((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
      ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).extract 4
      (((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).size = rest := by
    have hsz2 : ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
        ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).extract 4
        ((((RoutingCommand.nodeDelay d).toBytes ++ rest).extract 1
          ((RoutingCommand.nodeDelay d).toBytes ++ rest).size).size)).size = rest.size := by
      rw [ByteArray.size_extract, hrest0sz]; omega
    apply byteArray_ext_get!
    · exact hsz2
    · intro k hk
      have hkr : k < rest.size := by rw [← hsz2]; exact hk
      rw [get!_extract_from _ 4 k hk,
        get!_extract_from _ 1 (4 + k) (by rw [hrest0sz]; omega),
        show (1 + (4 + k)) = A2.size + k from by rw [hA2sz]; omega,
        hcmd, get!_append_right A2 rest k hkr]
  revert h0 h1 htag hle hd hrestTail
  generalize (RoutingCommand.nodeDelay d).toBytes ++ rest = b
  intro h0 h1 htag hle hd hrestTail
  unfold fromBytesOne
  simp only [h0, h1, Bool.false_eq_true, if_false, htag, hle, hd, hrestTail, pure, Except.pure]

/-- A slice of an all-zero buffer is all-zero. -/
private theorem extract_all_zero (b : ByteArray) (h : b.data.all (· == 0)) (lo hi : Nat) :
    (b.extract lo hi).data.all (· == 0) := by
  rw [Array.all_eq_true] at h ⊢
  intro i hi2
  have hsz : (b.extract lo hi).size = min hi b.size - lo := ByteArray.size_extract
  have hib : lo + i < b.size := by
    have : i < (b.extract lo hi).size := hi2
    omega
  have hbz := h (lo + i) hib
  show ((b.extract lo hi).data[i] == 0) = true
  have : (b.extract lo hi).data[i] = (b.extract lo hi)[i]'hi2 := rfl
  rw [this, ByteArray.getElem_extract]
  exact hbz

private theorem byteArray_all_zero_get! (b : ByteArray) (h : b.data.all (· == 0)) (i : Nat)
    (hi : i < b.size) : b.get! i = 0 := by
  rw [byteArray_get!_eq, getElem!_pos b i hi]
  have h' := Array.all_eq_true.mp h i (by simpa using hi)
  have hde : b.data[i]'(by simpa using hi) = b[i]'hi := rfl
  rw [beq_iff_eq] at h'
  rw [← hde]
  exact h'

/-- On an all-zero buffer, `fromBytesOne` returns no command. -/
private theorem fromBytesOne_zeros (b : ByteArray) (h : b.data.all (· == 0)) :
    ∃ rest, fromBytesOne b = .ok (none, rest) := by
  by_cases hsz0 : b.size = 0
  · exact ⟨b, by unfold fromBytesOne; simp only [hsz0, beq_self_eq_true, if_true, pure, Except.pure]⟩
  · have hb0 : b.get! 0 = 0 := byteArray_all_zero_get! b h 0 (by omega)
    have hsz0' : (b.size == 0) = false := by rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
    by_cases hsz1 : b.size = 1
    · refine ⟨ByteArray.empty, ?_⟩
      unfold fromBytesOne
      simp only [hsz0', Bool.false_eq_true, if_false]
      simp only [hsz1, hb0, beq_self_eq_true, if_true, pure, Except.pure]
    · have hrest0z : (b.extract 1 b.size).data.all (· == 0) := extract_all_zero b h 1 b.size
      have hsz1' : (b.size == 1) = false := by rw [Bool.eq_false_iff, Ne, beq_iff_eq]; omega
      refine ⟨ByteArray.empty, ?_⟩
      unfold fromBytesOne
      simp only [hsz0', Bool.false_eq_true, if_false]
      simp only [hsz1', hb0, hrest0z, beq_self_eq_true, if_true, Bool.false_eq_true, if_false,
        pure, Except.pure]

/-- `parseAllFuel` returns `.ok []` on an all-zero buffer. -/
private theorem parseAllFuel_zeros (fuel : Nat) (b : ByteArray) (h : b.data.all (· == 0)) :
    parseAllFuel fuel b = .ok [] := by
  cases fuel with
  | zero => rfl
  | succ fuel =>
    obtain ⟨rest, hrest⟩ := fromBytesOne_zeros b h
    unfold parseAllFuel
    simp only [hrest, pure, Except.pure, bind, Except.bind]

/-- Folding `commandsToBytes` onto a nonempty buffer equals prepending that buffer. -/
private theorem foldl_toBytes_append (l : List RoutingCommand) (init : ByteArray) :
    l.foldl (fun acc c => acc ++ c.toBytes) init
      = init ++ l.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty := by
  induction l generalizing init with
  | nil => simp
  | cons hd tl ih =>
    rw [List.foldl_cons, List.foldl_cons, ih (init ++ hd.toBytes),
      ih (ByteArray.empty ++ hd.toBytes), ByteArray.empty_append, ByteArray.append_assoc]

/-- Parsing serialized commands followed by any all-zero padding recovers the commands, given
enough fuel and no `.null` among them. -/
theorem parseAllFuel_append_zeros (cmds : List RoutingCommand) (hn : ∀ c ∈ cmds, c ≠ .null)
    (zeros : ByteArray) (hzeros : zeros.data.all (· == 0)) (fuel : Nat)
    (hfuel : cmds.length ≤ fuel) :
    parseAllFuel fuel (cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros)
      = .ok cmds := by
  induction cmds generalizing fuel with
  | nil =>
    simp only [List.foldl_nil, ByteArray.empty_append]
    exact parseAllFuel_zeros fuel zeros hzeros
  | cons hd tl ih =>
    obtain ⟨fuel', rfl⟩ : ∃ fuel', fuel = fuel' + 1 := by
      rcases fuel with _ | fuel'
      · simp at hfuel
      · exact ⟨fuel', rfl⟩
    have hnd : hd ≠ .null := hn hd (List.mem_cons_self)
    have hntl : ∀ c ∈ tl, c ≠ .null := fun c hc => hn c (List.mem_cons_of_mem hd hc)
    have hfuel' : tl.length ≤ fuel' := by
      simp only [List.length_cons] at hfuel; omega
    have hbuf : (hd :: tl).foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros
        = hd.toBytes ++ (tl.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros) := by
      rw [List.foldl_cons, ByteArray.empty_append, foldl_toBytes_append,
        ByteArray.append_assoc]
    rw [hbuf]
    have hstep : fromBytesOne (hd.toBytes
        ++ (tl.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros))
        = .ok (some hd, tl.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros) := by
      cases hd with
      | nextNodeHop id mac => exact fromBytesOne_toBytes_append_nextNodeHop id mac _
      | recipient id => exact fromBytesOne_toBytes_append_recipient id _
      | surbReply id => exact fromBytesOne_toBytes_append_surbReply id _
      | nodeDelay d => exact fromBytesOne_toBytes_append_nodeDelay d _
      | null => exact absurd rfl hnd
    unfold parseAllFuel
    simp only [hstep, pure, Except.pure, bind, Except.bind, ih hntl fuel' hfuel']

/-- Every command encodes to at least one byte. -/
private theorem toBytes_size_pos (c : RoutingCommand) : 1 ≤ c.toBytes.size := by
  cases c with
  | nextNodeHop id mac =>
    simp [RoutingCommand.toBytes, ByteArray.size_append, size_ofVector]
  | recipient id => simp [RoutingCommand.toBytes, ByteArray.size_append, size_ofVector]
  | surbReply id => simp [RoutingCommand.toBytes, ByteArray.size_append, size_ofVector]
  | nodeDelay d => simp [RoutingCommand.toBytes, ByteArray.size_append, size_ofVector]
  | null => decide

private theorem length_le_foldl_toBytes_size (cmds : List RoutingCommand) :
    cmds.length ≤ (cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty).size := by
  induction cmds with
  | nil => simp
  | cons hd tl ih =>
    rw [List.foldl_cons, ByteArray.empty_append, foldl_toBytes_append, ByteArray.size_append,
      List.length_cons]
    have := toBytes_size_pos hd
    omega

/-- `parseAll` undoes `commandsToBytes` followed by any all-zero padding. -/
theorem parseAll_append_zeros (cmds : List RoutingCommand) (hn : ∀ c ∈ cmds, c ≠ .null)
    (zeros : ByteArray) (hzeros : zeros.data.all (· == 0)) :
    parseAll (cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty ++ zeros) = .ok cmds := by
  unfold parseAll
  apply parseAllFuel_append_zeros cmds hn zeros hzeros
  rw [ByteArray.size_append]
  have := length_le_foldl_toBytes_size cmds
  omega

end CryptWalker.Protocols.Sphinx.Commands
