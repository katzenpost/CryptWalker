/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

-- Security preserving KEM combiner

import Mathlib.Data.ByteArray

import CryptWalker.kem.kem
namespace CryptWalker.kem.combiner
open CryptWalker.kem.kem

-- alternative combiner would use a type parameter

structure Combiner where
  hash : ByteArray → ByteArray
  KEMs : List (Σ α : Type, KEM α × α)


structure PrivateKey where
  data : List ByteArray

structure PublicKey where
  data : List ByteArray

def splitByteArray (bytes : ByteArray) (n : Nat) : ByteArray × ByteArray :=
  let part1 := bytes.extract 0 n
  let part2 := bytes.extract n bytes.size
  (part1, part2)

def splitByteArrayIntoChunks (bytes : ByteArray) (sizes : List Nat) : Option (List ByteArray) :=
  let rec aux (bytes : ByteArray) (sizes : List Nat) (acc : List ByteArray) : Option (List ByteArray) :=
    match sizes with
    | [] =>
      if bytes.isEmpty then
        some acc.reverse
      else
        none
    | size :: sizesTail =>
      if bytes.size < size then
        none
      else
        let (part1, part2) := splitByteArray bytes size
        aux part2 sizesTail (part1 :: acc)
  aux bytes sizes []

instance : kem.Key PrivateKey where
  encode : PrivateKey → ByteArray := fun (key : PrivateKey) =>
    key.data.foldl (init:= ByteArray.empty) fun acc byteArray => acc ++ byteArray

  decode {α : Type} (kem : KEM α Combiner) (c : Combiner) (bytes : ByteArray) : Option PrivateKey :=
    if bytes.size ≠ kem.privateKeySize then
      none
    else
      let sizes := c.KEMs.foldl (f := fun acc x => acc ++ [x.snd.fst.privateKeySize]) []
      match splitByteArrayIntoChunks bytes sizes with
      | none => none
      | some keys => some { data := keys}


instance : kem.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) =>
    key.data.foldl (init:= ByteArray.empty) fun acc byteArray => acc ++ byteArray
  decode : ByteArray → Option PublicKey := fun (bytes : ByteArray) =>
    if bytes.size ≠ kem.publicKeySize then
      none
    blah

    --some (PublicKey.mk bytes)
    -- FIXME
    none






end CryptWalker.kem.combiner
