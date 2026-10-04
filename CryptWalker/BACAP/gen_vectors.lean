/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.BACAP.API
import CryptWalker.BACAP.Types
import CryptWalker.Util.newhex

/-! # Generate the BACAP vector files from hpqc's inputs

Reads `CryptWalker/testdata/bacap_inputs.json`, vendored from hpqc's `testvectors/bacap/inputs.json`,
and generates the eight BACAP vector files with this implementation. hpqc's Go generator and its
Python port generate the same files from the same inputs; the three must agree on every value.

    CryptWalker-BACAP-gen_vectors --check     compare with the vendored hpqc files
    CryptWalker-BACAP-gen_vectors DIR         write the files into DIR -/

open Lean
open CryptWalker.BACAP.Types
open CryptWalker.BACAP.Ratchet
open CryptWalker.Hash.HKDF
open CryptWalker.Util.newhex

abbrev Gen := ExceptT String IO

def hexOf {n} (v : Vector UInt8 n) : String := byteArrayToHex ⟨v.toArray⟩

def field (j : Json) (k : String) : Gen Json := liftExcept (j.getObjVal? k)
def str (j : Json) (k : String) : Gen String := do liftExcept (← field j k).getStr?
def nat (j : Json) (k : String) : Gen Nat := do liftExcept (← field j k).getNat?
def boolField (j : Json) (k : String) : Gen Bool := do liftExcept (← field j k).getBool?
def arr (j : Json) (k : String) : Gen (Array Json) := do liftExcept (← field j k).getArr?
def has (j : Json) (k : String) : Bool := match j.getObjVal? k with
  | .ok Json.null => false
  | .ok _ => true
  | .error _ => false

def toVec (n : Nat) (b : ByteArray) : Gen (Vector UInt8 n) :=
  if h : b.data.size = n then pure ⟨b.data, h⟩ else throw s!"expected {n} bytes, got {b.size}"

/-- The Go generator's `deterministicBytes`: HKDF-BLAKE2b-512 over a label. -/
def deterministicBytes (label name : String) (n : Nat) : ByteArray :=
  let prk := blake2b512_hkdf.extract ByteArray.empty ("hpqc-vector-seed-" ++ label).toUTF8
  ⟨(blake2b512_hkdf.expand prk name.toUTF8 n).toArray⟩

/-- A byte string from inputs.json: hex, utf8, a repeated byte, or derived from a label. -/
def specBytes (j : Json) : Gen ByteArray := do
  if j == Json.null then return ByteArray.empty
  if has j "hex" then
    match hexStringToByteArray (← str j "hex") with
    | some b => return b
    | none => throw "bad hex"
  if has j "utf8" then return (← str j "utf8").toUTF8
  if has j "repeat" then
    let r ← field j "repeat"
    return ⟨Array.replicate (← nat r "count") (← nat r "byte").toUInt8⟩
  if has j "derive" then
    let d ← field j "derive"
    return deterministicBytes (← str d "label") (← str d "name") (← nat d "length")
  throw s!"empty bytes spec {j.compress}"

def optBytes (j : Json) (k : String) : Gen ByteArray :=
  if has j k then do specBytes (← field j k) else pure ByteArray.empty

def opt {α} (o : Option α) (what : String) : Gen α :=
  match o with | some a => pure a | none => throw what

def advanced (m : MessageBoxIndex) (by_ : Nat) : Gen MessageBoxIndex :=
  if by_ = 0 then pure m
  else opt (m.advanceIndexTo (m.idx64 + by_.toUInt64)) "advance rewinds"

def u64LE (b : ByteArray) (off : Nat) : UInt64 :=
  (List.range 8).foldl (fun acc i => acc ||| ((b[off + i]!).toUInt64 <<< (8 * i).toUInt64)) 0

def buildCap (j : Json) : Gen WriteCap := do
  let seed ← toVec 32 (← specBytes (← field j "seed"))
  let first ← if has j "index" then do
      pure (unmarshalMessageBoxIndex (← toVec MessageBoxIndexSize (← specBytes (← field j "index"))))
    else do
      let s ← field j "start_idx64"
      let start : UInt64 ← match s.getNat? with
        | .ok n => pure n.toUInt64
        | .error _ => do
          let b ← specBytes (← field s "irwin_hall")
          let b := (b.set! 7 (b[7]! &&& 0x3f)).set! 15 (b[15]! &&& 0x3f)
          pure (u64LE b 0 + u64LE b 8)
      let hs ← toVec 32 (← specBytes (← field j "hkdf_state"))
      let seedIdx : MessageBoxIndex :=
        { idx64 := start, curBlindingFactor := Vector.replicate 32 0,
          curEncryptionKey := Vector.replicate 32 0, hkdfState := hs }
      opt seedIdx.nextIndex "first index"
  pure { rootSeed := seed, messageBoxIndex := first }

def capBlob (wc : WriteCap) : String := hexOf (marshalWriteCap wc)
def idxHex (m : MessageBoxIndex) : String := hexOf (marshalMessageBoxIndex m)

/-- Whether stepping the read cap's own index forward reaches `idx`. -/
def reachable (rc : ReadCap) (idx : MessageBoxIndex) : Bool :=
  let start := rc.messageBoxIndex
  idx.idx64 ≥ start.idx64 &&
    ((start.advanceIndexTo idx.idx64).map idxHex) == some (idxHex idx)

def flipped (b : ByteArray) (i : Nat) : ByteArray := b.set! i (b[i]! ^^^ 1)

def num (n : Nat) : Json := Json.num n
def s (x : String) : Json := Json.str x

def generate (inp : Json) : Gen (List (String × Json)) := do
  let mut capMap : Std.HashMap String WriteCap := {}
  for c in ← arr inp "caps" do
    capMap := capMap.insert (← str c "name") (← buildCap c)
  let caps := capMap
  let cap (name : String) : Gen WriteCap := opt caps[name]? s!"unknown cap {name}"
  let file (name : String) (vs : Array Json) : Gen Json := do
    let f ← field (← field inp "files") name
    pure (Json.mkObj [("format_version", num 1),
      ("generator", s "github.com/katzenpost/hpqc/testvectors/cmd/generate"),
      ("primitive", s (← str f "primitive")), ("description", s (← str f "description")),
      ("vectors", Json.arr vs)])

  let mut mbi := #[]
  for v in ← arr inp "message_box_index" do
    let idx := (← cap (← str v "cap")).messageBoxIndex
    let by_ ← nat v "advance_by"
    mbi := mbi.push (Json.mkObj [("name", s (← str v "name")), ("initial_index_hex", s (idxHex idx)),
      ("advance_to", num (idx.idx64.toNat + by_)), ("expected_index_hex", s (idxHex (← advanced idx by_)))])

  let mut box := #[]
  for v in ← arr inp "box_id" do
    let wc ← cap (← str v "cap")
    let by_ ← nat v "advance_by"
    let idx ← advanced wc.messageBoxIndex by_
    let ctx ← optBytes v "ctx"
    let useCtx ← boolField v "use_context"
    let b := if useCtx then idx.boxIDForContext wc.readCap ctx else idx.deriveMessageBoxID wc.rootPublicKey
    box := box.push (Json.mkObj [("name", s (← str v "name")), ("writecap_hex", s (capBlob wc)),
      ("advance_by", num by_), ("ctx_hex", s (byteArrayToHex ctx)), ("use_context", Json.bool useCtx),
      ("expected_box_id_hex", s (hexOf b))])

  let mut enc := #[]
  for v in ← arr inp "encrypt" do
    let wc ← cap (← str v "cap")
    let by_ ← nat v "advance_by"
    let idx ← advanced wc.messageBoxIndex by_
    let ctx ← specBytes (← field v "ctx")
    let pt ← specBytes (← field v "plaintext")
    let (b, ct, sig) := idx.encryptForContext wc ctx pt
    if idx.decryptForContext b ctx ct sig != some pt then throw s!"{← str v "name"}: round trip"
    enc := enc.push (Json.mkObj [("name", s (← str v "name")), ("writecap_hex", s (capBlob wc)),
      ("advance_by", num by_), ("ctx_hex", s (byteArrayToHex ctx)), ("plaintext_hex", s (byteArrayToHex pt)),
      ("expected_box_id_hex", s (hexOf b)), ("expected_ciphertext_hex", s (byteArrayToHex ct)),
      ("expected_signature_hex", s (hexOf sig))])

  let mut muts := #[]
  for v in ← arr inp "mutate_kdf_state" do
    let wc ← cap (← str v "cap")
    let by_ ← nat v "advance_by"
    let salt ← specBytes (← field v "salt")
    let rctx ← specBytes (← field v "read_ctx")
    let m := (← advanced wc.messageBoxIndex by_).mutateKDFState salt
    muts := muts.push (Json.mkObj [("name", s (← str v "name")), ("writecap_hex", s (capBlob wc)),
      ("advance_by", num by_), ("salt_hex", s (byteArrayToHex salt)), ("read_ctx_hex", s (byteArrayToHex rctx)),
      ("expected_mutated_index_hex", s (idxHex m)),
      ("expected_mutated_box_id_hex", s (hexOf (m.boxIDForContext wc.readCap rctx)))])

  let mut lay := #[]
  for v in ← arr inp "layout" do
    let wc ← cap (← str v "cap")
    let rc := wc.readCap
    lay := lay.push (Json.mkObj [("name", s (← str v "name")), ("writecap_hex", s (capBlob wc)),
      ("expected_root_public_key_hex", s (hexOf rc.rootPublicKey)),
      ("expected_readcap_hex", s (hexOf (marshalReadCap rc))),
      ("expected_index_hex", s (idxHex wc.messageBoxIndex)),
      ("expected_idx64", num wc.messageBoxIndex.idx64.toNat)])

  let mut tomb := #[]
  for v in ← arr inp "tombstone" do
    let wc ← cap (← str v "cap")
    let by_ ← nat v "advance_by"
    let idx ← advanced wc.messageBoxIndex by_
    let ctx ← specBytes (← field v "ctx")
    let (b, sig) := idx.signBox wc ctx ByteArray.empty
    if idx.decryptForContext b ctx ByteArray.empty sig != some ByteArray.empty then
      throw s!"{← str v "name"}: tombstone does not open"
    tomb := tomb.push (Json.mkObj [("name", s (← str v "name")), ("writecap_hex", s (capBlob wc)),
      ("advance_by", num by_), ("ctx_hex", s (byteArrayToHex ctx)), ("expected_box_id_hex", s (hexOf b)),
      ("expected_signature_hex", s (hexOf sig))])

  let mut pos := #[]
  for v in ← arr inp "position" do
    let wc ← cap (← str v "cap")
    let start := wc.messageBoxIndex
    let kind ← str v "kind"
    let (rc, idx) ← match kind with
      | "advance" => do pure (wc.readCap, ← advanced start (← nat v "advance_by"))
      | "foreign" => do
        let other := (← cap (← str v "other_cap")).messageBoxIndex
        pure (wc.readCap, { other with idx64 := start.idx64 + (← nat v "idx64_offset").toUInt64 })
      | "mutated" => do
        pure (wc.readCap, ← advanced (start.mutateKDFState (← specBytes (← field v "salt"))) (← nat v "advance_by"))
      | "tampered" => do
        if (← str v "field") ≠ "hkdf_state" then throw "tampered: unknown field"
        let t ← advanced start (← nat v "advance_by")
        let i ← nat v "byte"
        let x := (← nat v "xor").toUInt8
        let hs := Vector.ofFn fun k : Fin 32 => if k.val = i then t.hkdfState[k] ^^^ x else t.hkdfState[k]
        pure (wc.readCap, { t with hkdfState := hs })
      | "behind" => do
        pure (wc.readCap.withMessageBoxIndex (← advanced start (← nat v "rebase_advance_by")), start)
      | k => throw s!"unknown position kind {k}"
    pos := pos.push (Json.mkObj [("name", s (← str v "name")), ("readcap_hex", s (hexOf (marshalReadCap rc))),
      ("index_hex", s (idxHex idx)), ("reachable", Json.bool (reachable rc idx)),
      ("description", s (← str v "description"))])

  let mut neg := #[]
  for v in ← arr inp "negative" do
    let op ← str v "operation"
    -- Fields as Go writes them: empty strings and an unset advance_to left out,
    -- advance_by always present.
    let mut fs : List (String × Json) := []
    let mut advBy : Nat := 0
    match op with
    | "advance_index_to" =>
      let idx := (← cap (← str v "cap")).messageBoxIndex
      fs := [("index_hex", s (idxHex idx)), ("advance_to", num (idx.idx64.toNat - (← nat v "rewind_by")))]
    | "next_index" =>
      fs := [("index_hex", s (idxHex (← advanced (← cap (← str v "cap")).messageBoxIndex (← nat v "index_advance_by"))))]
    | "decrypt" | "verify_box" | "open" =>
      let wc ← cap (← str v "cap")
      let src ← field v "source"
      let sidx ← advanced wc.messageBoxIndex (← nat src "advance_by")
      let sctx ← specBytes (← field src "ctx")
      let (b, ct, sig) ← match ← str src "kind" with
        | "encrypt" => do
          let (b, ct, sig) := sidx.encryptForContext wc sctx (← specBytes (← field src "plaintext"))
          pure (b, ct, ByteArray.mk sig.toArray)
        | "tombstone" => do
          let (b, sig) := sidx.signBox wc sctx ByteArray.empty
          pure (b, ByteArray.empty, ByteArray.mk sig.toArray)
        | k => throw s!"unknown source kind {k}"
      let (ct, sig) ← if has v "flip" then do
          let f ← field v "flip"
          match ← str f "field" with
          | "ciphertext" => pure (flipped ct (← nat f "byte"), sig)
          | "signature" => pure (ct, flipped sig (← nat f "byte"))
          | k => throw s!"unknown flip field {k}"
        else pure (ct, sig)
      advBy ← nat v "advance_by"
      fs := [("writecap_hex", s (capBlob wc)), ("ctx_hex", s (byteArrayToHex (← optBytes v "ctx"))),
        ("box_id_hex", s (hexOf b)), ("ciphertext_hex", s (byteArrayToHex ct)),
        ("signature_hex", s (byteArrayToHex sig))]
    | "parse_message_box_index" | "parse_read_cap" | "parse_write_cap" =>
      let bl ← field v "blob"
      let wc ← cap (← str bl "cap")
      let blob : ByteArray ← match ← str bl "from" with
        | "index" => pure ⟨(marshalMessageBoxIndex wc.messageBoxIndex).toArray⟩
        | "readcap" => pure ⟨(marshalReadCap wc.readCap).toArray⟩
        | "writecap" => pure ⟨(marshalWriteCap wc).toArray⟩
        | k => throw s!"unknown blob source {k}"
      let e ← field bl "edit"
      let blob ← match ← str e "kind" with
        | "empty" => pure ByteArray.empty
        | "truncate" => pure (blob.extract 0 (blob.size - (← nat e "count")))
        | "append_zero" => pure (blob ++ ⟨Array.replicate (← nat e "count") 0⟩)
        | "replace" => do
          let off ← nat e "offset"
          let w ← if has e "public_key_of" then do
              pure ⟨(marshalWriteCap (← cap (← str e "public_key_of"))).toArray.extract 32 64⟩
            else specBytes (← field e "bytes")
          pure ((List.range w.size).foldl (fun acc i => acc.set! (off + i) w[i]!) blob)
        | k => throw s!"unknown blob edit {k}"
      fs := [("blob_hex", s (byteArrayToHex blob))]
    | k => throw s!"unknown operation {k}"
    let get (k : String) : Option Json := fs.lookup k
    let keep (k : String) : List (String × Json) := match get k with
      | some (Json.str "") => []
      | some j => [(k, j)]
      | none => []
    neg := neg.push (Json.mkObj ([("name", s (← str v "name")), ("operation", s op),
      ("category", s (← str v "category")), ("description", s (← str v "description"))] ++
      keep "blob_hex" ++ keep "index_hex" ++ keep "advance_to" ++ keep "writecap_hex" ++
      [("advance_by", num advBy)] ++ keep "ctx_hex" ++ keep "box_id_hex" ++ keep "ciphertext_hex" ++
      keep "signature_hex"))

  pure [("message_box_index", ← file "message_box_index" mbi), ("box_id", ← file "box_id" box),
    ("encrypt", ← file "encrypt" enc), ("mutate_kdf_state", ← file "mutate_kdf_state" muts),
    ("layout", ← file "layout" lay), ("tombstone", ← file "tombstone" tomb),
    ("position", ← file "position" pos), ("negative", ← file "negative" neg)]

/-- JSON values compared field by field, so object key order does not matter. -/
partial def sameJson : Json → Json → Bool
  | .obj a, .obj b =>
    let as := a.toArray
    as.size == b.toArray.size && as.all fun (k, v) => match b.get? k with
      | some w => sameJson v w
      | none => false
  | .arr a, .arr b => a.size == b.size && (a.zip b).all fun (x, y) => sameJson x y
  | a, b => a == b

def main (args : List String) : IO UInt32 := do
  let raw ← IO.FS.readFile "CryptWalker/testdata/bacap_inputs.json"
  let inp ← IO.ofExcept (Json.parse raw)
  let files ← match ← (generate inp).run with
    | .ok fs => pure fs
    | .error e => do IO.eprintln s!"generation failed: {e}"; return 1
  match args with
  | ["--check"] =>
    let mut ok := true
    for (name, gen) in files do
      let committed ← IO.ofExcept (Json.parse (← IO.FS.readFile s!"CryptWalker/testdata/{name}.json"))
      if sameJson gen committed then
        IO.println s!"  ok    {name}.json"
      else
        ok := false
        IO.println s!"  FAIL  {name}.json differs from what inputs.json generates"
    if ok then IO.println "the Lean implementation generates every BACAP vector file"; pure 0
    else IO.eprintln "some BACAP vector files differ"; pure 1
  | [dir] =>
    IO.FS.createDirAll dir
    for (name, gen) in files do
      IO.FS.writeFile s!"{dir}/{name}.json" (gen.pretty ++ "\n")
      IO.println s!"wrote {dir}/{name}.json"
    pure 0
  | _ => do IO.eprintln "usage: CryptWalker-BACAP-gen_vectors (--check | DIR)"; pure 2
