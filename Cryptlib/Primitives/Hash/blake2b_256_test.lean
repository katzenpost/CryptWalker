/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Primitives.Hash.Blake2b
import Cryptlib.Util.newhex

/-! # BLAKE2b-256 (unkeyed and keyed) known-answer tests

Checks `Blake2b.hash256`/`hash256Keyed` against `testdata/blake2b_256.json`, from hpqc. -/

open Lean
open Cryptlib.Util.newhex
open Cryptlib.Primitives.Hash.Blake2b (hash256 hash256Keyed)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def hexOfV {n} (v : Vector UInt8 n) : String := byteArrayToHex ⟨v.toArray⟩
def hexOfB (b : ByteArray) : String := byteArrayToHex b

def main : IO UInt32 := do
  let raw ← IO.FS.readFile "testdata/blake2b_256.json"
  match Json.parse raw >>= (·.getObjVal? "vectors") >>= Json.getArr? with
  | .error e => IO.eprintln e; pure 1
  | .ok arr =>
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let key ← field j "key_hex"
        let msg ← field j "msg_hex"
        let want ← field j "digest_hex"
        pure (name, key, msg, want) : Except String _) with
      | .error e => IO.eprintln e; ok := false
      | .ok (name, key, msg, want) =>
        let got := hexOfV (if key.size = 0 then hash256 msg else hash256Keyed key msg)
        if got == hexOfB want then
          IO.println s!"  ok    {name}"
        else
          ok := false
          IO.println s!"  FAIL  {name}"
          IO.println s!"          want {hexOfB want}"
          IO.println s!"          got  {got}"
    if ok then
      IO.println "all BLAKE2b-256 vectors passed"
      pure 0
    else
      IO.eprintln "BLAKE2b-256 vectors FAILED"
      pure 1
