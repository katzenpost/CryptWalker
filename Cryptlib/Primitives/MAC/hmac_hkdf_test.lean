import Lean.Data.Json

import Cryptlib.Primitives.Hash.Hash
import Cryptlib.Primitives.Hash.Sha2
import Cryptlib.Primitives.Hash.Sha512
import Cryptlib.Primitives.Hash.Blake2s
import Cryptlib.Primitives.Hash.HKDF
import Cryptlib.Primitives.KDF.HKDF
import Cryptlib.Primitives.MAC.HMAC
import Cryptlib.Util.newhex

open Lean
open Cryptlib.Primitives.Hash.Hash
open Cryptlib.Util.newhex

/-! RFC 4231 HMAC and RFC 5869 HKDF vectors (`testdata/hmac_hkdf.json`), run against the generic
constructions at every `Hash` instance named in the file. -/

def hashes : List Hash :=
  [Cryptlib.Primitives.Hash.Sha2.Sha256.Scheme, Cryptlib.Primitives.Hash.Sha512.Scheme,
   Cryptlib.Primitives.Hash.HKDF.blake2b_hashScheme, Cryptlib.Primitives.Hash.Blake2s.Scheme]

def hashByName (name : String) : Option Hash := hashes.find? (·.name == name)

def hexField (j : Json) (k : String) : Except String ByteArray := do
  match hexStringToByteArray (← (← j.getObjVal? k).getStr?) with
  | some b => pure b
  | none => throw s!"{k} is not valid hex"

def bytes {n} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

def runHMAC (j : Json) : Except String (Option Bool) := do
  let some H := hashByName (← (← j.getObjVal? "hash").getStr?) | pure none
  let tag := Cryptlib.Primitives.MAC.HMAC.hmac H (← hexField j "key_hex") (← hexField j "msg_hex")
  pure (some (bytes tag == (← hexField j "tag_hex")))

def runHKDF (j : Json) : Except String (Option Bool) := do
  let some H := hashByName (← (← j.getObjVal? "hash").getStr?) | pure none
  let prk := Cryptlib.Primitives.KDF.HKDF.extract H (← hexField j "salt_hex") (← hexField j "ikm_hex")
  let len ← (← j.getObjVal? "length").getNat?
  let okm := Cryptlib.Primitives.KDF.HKDF.expand H (bytes prk) (← hexField j "info_hex") len
  let structured := (Cryptlib.Primitives.Hash.HKDF.ofHash H).expand prk (← hexField j "info_hex") len
  pure (some (bytes prk == (← hexField j "prk_hex") && okm == (← hexField j "okm_hex")
    && bytes structured == okm))

def main : IO UInt32 := do
  let json ← IO.ofExcept (Json.parse (← IO.FS.readFile "testdata/hmac_hkdf.json"))
  let mut passed := 0
  let mut skipped := 0
  let mut failed := 0
  for (kind, run) in [("hmac", runHMAC), ("hkdf", runHKDF)] do
    for v in ← IO.ofExcept ((← IO.ofExcept (json.getObjVal? kind)).getArr?) do
      let label := s!"{kind} {(v.getObjValD "hash").getStr?.toOption.getD "?"} {(v.getObjValD "name").getStr?.toOption.getD "?"}"
      match run v with
      | .ok (some true) => passed := passed + 1
      | .ok none => skipped := skipped + 1
      | .ok (some false) => failed := failed + 1; IO.println s!"  FAIL  {label}"
      | .error e => failed := failed + 1; IO.println s!"  FAIL  {label}: {e}"
  IO.println s!"hmac/hkdf: {passed}/{passed + failed} passed, {skipped} skipped (hash not implemented)"
  pure (if failed == 0 then 0 else 1)
