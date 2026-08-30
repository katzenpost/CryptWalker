/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Hash.Sha512
import CryptWalker.Util.newhex

/-!
# SHA-512 known-answer tests

Reads `testdata/sha512.json`, generated from Go's `crypto/sha512` by
`hpqc/testvectors/cmd/generate` and vendored here (hpqc is a separate repository, so it cannot
be symlinked). `testdata/sha512.json.sha256` records which copy this is.

Two of the vectors matter more than the rest: `two_blocks_boundary_112` and `three_blocks_300`
are the only inputs whose padding spills past a single 128-byte block, so they are what
exercises the chaining between compression-function calls. Everything shorter would pass even
with the block loop broken.
-/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Hash.Sha512

structure HashVec where
  name   : String
  input  : ByteArray
  output : ByteArray

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def parseVec (j : Json) : Except String HashVec := do
  pure {
    name   := ← (← j.getObjVal? "name").getStr?
    input  := ← field j "input_hex"
    output := ← field j "output_hex"
  }

def parseFile (s : String) : Except String (Array HashVec) := do
  let j ← Json.parse s
  let prim ← (← j.getObjVal? "primitive").getStr?
  if prim ≠ "sha512" then
    throw s!"unexpected primitive: {prim}"
  (← (← j.getObjVal? "vectors").getArr?).mapM parseVec

def hexOf {n} (v : Vector UInt8 n) : String := byteArrayToHex ⟨v.toArray⟩

def main : IO UInt32 := do
  let path := "testdata/sha512.json"
  let raw ← IO.FS.readFile path
  match parseFile raw with
  | .error e => do IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok vs => do
    IO.println s!"SHA-512 known-answer tests ({vs.size} vectors from hpqc)"
    let mut ok := true
    for v in vs do
      let want := byteArrayToHex v.output
      let got  := hexOf (sha512 v.input)
      -- how many compression-function calls this input needs
      let blocks := (v.input.size + 1 + 16 + 127) / 128
      if want == got then
        IO.println s!"  ok    {v.input.size}B, {blocks} block(s)  {v.name}"
      else
        ok := false
        IO.println s!"  FAIL  {v.name}"
        IO.println s!"          want {want}"
        IO.println s!"          got  {got}"
    IO.println ""
    if !ok then
      IO.eprintln "SHA-512 known-answer tests FAILED"
      return 1
    -- The interface laws are proved, not tested; exercise the incremental path anyway so a
    -- future memory-bounded `update` cannot silently diverge from `hash`.
    let m := "the quick brown fox jumps over the lazy dog, twice, at some length".toUTF8
    let oneShot := hexOf (Scheme.hash m)
    let chunked := hexOf (Scheme.finalize
      (Scheme.update (Scheme.update Scheme.init (m.extract 0 20)) (m.extract 20 m.size)))
    if oneShot ≠ chunked then
      IO.eprintln s!"incremental mismatch: {oneShot} vs {chunked}"
      return 1
    IO.println "incremental and one-shot agree"
    IO.println s!"all {vs.size} vectors passed"
    pure 0
