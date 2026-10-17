/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Primitives.Hash.Blake2b
import Cryptlib.Util.newhex

/-! # BLAKE2Xb known-answer tests

Checks `Blake2b.xof` against `testdata/blake2b_xof.json`, from hpqc. `xof_size` is the configured
size and `length` the number of bytes read. -/

open Lean
open Cryptlib.Util.newhex
open Cryptlib.Primitives.Hash.Blake2b (xof)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def hexOfB (b : ByteArray) : String := byteArrayToHex b

def main : IO UInt32 := do
  let raw ← IO.FS.readFile "testdata/blake2b_xof.json"
  match Json.parse raw >>= (·.getObjVal? "vectors") >>= Json.getArr? with
  | .error e => IO.eprintln e; pure 1
  | .ok arr =>
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let key ← field j "key_hex"
        let msg ← field j "msg_hex"
        let xofSize ← (← j.getObjVal? "xof_size").getNat?
        let length ← (← j.getObjVal? "length").getNat?
        let want ← field j "out_hex"
        pure (name, key, msg, xofSize, length, want) : Except String _) with
      | .error e => IO.eprintln e; ok := false
      | .ok (name, key, msg, xofSize, length, want) =>
        let gotHex := hexOfB (xof key xofSize length msg)
        if gotHex == hexOfB want then
          IO.println s!"  ok    {name}"
        else
          ok := false
          IO.println s!"  FAIL  {name}"
          IO.println s!"          want {hexOfB want}"
          IO.println s!"          got  {gotHex}"
    if ok then
      IO.println "all BLAKE2b XOF vectors passed"
      pure 0
    else
      IO.eprintln "BLAKE2b XOF vectors FAILED"
      pure 1
