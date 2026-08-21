/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import CryptWalker.KEM.KEM

namespace CryptWalker.KEM.Combiner
open CryptWalker.KEM.KEM

-- Security preserving KEM combiner

/-
SplitPRF can be used with any number of KEMs
and it implement split PRF KEM combiner as:

  cct := cct1 || cct2 || cct3 || ...
       return H(ss1 || cct) XOR H(ss2 || cct) XOR H(ss3 || cct)

in order to retain IND-CCA2 security
as described in KEM Combiners  https://eprint.iacr.org/2018/024.pdf
by Federico Giacon, Felix Heuer, and Bertram Poettering
-/

def hashSize := 32

def xorByteArrays (a b : { s : ByteArray // s.size = 32 }) : { s : ByteArray // s.size = 32 } :=
  ⟨ByteArray.mk (Array.zipWith (fun x y => x ^^^ y) a.val.data b.val.data), by
    have ha : a.val.data.size = 32 := a.property
    have hb : b.val.data.size = 32 := b.property
    simp only [ByteArray.size, Array.size_zipWith, ha, hb, Nat.min_self]
    ⟩

def splitPRF (hash : ByteArray → { s : ByteArray // s.size = 32 })
    (ss : List ByteArray) (ct : List ByteArray) : { s : ByteArray // s.size = 32 } :=
  let bigCt := ct.foldl (· ++ ·) ByteArray.empty
  (ss.map (fun x => hash (x ++ bigCt))).foldl xorByteArrays ⟨ByteArray.mk (Array.replicate 32 0), by
    rfl⟩

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

def combinerEncapsulateWith (hash : ByteArray → { out : ByteArray // out.size = 32 }) (KEMs : List KEM)
    (seed : { s : ByteArray // s.size = 32 }) (pubkey : PublicKey) : Option (ByteArray × ByteArray) := do
  let pairs ← (((List.range KEMs.length).zip KEMs).zip pubkey.data).mapM fun ((i, kem), pkChunk) => do
    let pk ← kem.decodePublicKey pkChunk
    kem.encapsulateWith (hash (seed.val ++ ByteArray.mk #[UInt8.ofNat i])) pk
  let cts := pairs.map Prod.fst
  pure (cts.foldl (· ++ ·) ByteArray.empty, (splitPRF hash (pairs.map Prod.snd) cts).val)

def createKEMCombiner (name : String) (hash : ByteArray → { s : ByteArray // s.size = 32 }) (KEMs : List KEM) : KEM :=
{
  PublicKeyType := PublicKey,
  PrivateKeyType := PrivateKey,
  privateKeySize := KEMs.foldl (fun acc x => acc + x.privateKeySize) 0,
  publicKeySize := KEMs.foldl (fun acc x => acc + x.publicKeySize) 0,
  ciphertextSize := KEMs.foldl (fun acc x => acc + x.ciphertextSize) 0,
  name := name,

  generateKeyPair := do
    let mut pubkeyData : List ByteArray := []
    let mut privkeyData : List ByteArray := []
    for kem in KEMs do
      let (newpubkey, newprivkey) ← kem.generateKeyPair
      pubkeyData := pubkeyData ++ [kem.encodePublicKey newpubkey]
      privkeyData := privkeyData ++ [kem.encodePrivateKey newprivkey]
    pure ({ data := pubkeyData }, { data := privkeyData }),

  generateKeyPairWith := fun seed =>
    let pairs := ((List.range KEMs.length).zip KEMs).map (fun (i, kem) =>
      let derived := hash (seed.val ++ ByteArray.mk #[UInt8.ofNat i])
      let (pk, sk) := kem.generateKeyPairWith derived
      (kem.encodePublicKey pk, kem.encodePrivateKey sk))
    ({ data := pairs.map Prod.fst }, { data := pairs.map Prod.snd }),

  encapsulateWith := combinerEncapsulateWith hash KEMs,

  encapsulate := fun pubkey => do
    let mut raw : ByteArray := ByteArray.empty
    for _ in [0:32] do
      let b ← IO.rand 0 255
      raw := raw.push (UInt8.ofNat b)
    match combinerEncapsulateWith hash KEMs (hash raw) pubkey with
    | none => panic! "encapsulation failed"
    | some result => pure result,

  decapsulate := fun privkey ciphertext =>
    let sizes := KEMs.map (fun x => x.ciphertextSize)
    match splitByteArrayIntoChunks ciphertext sizes with
    | none => panic! "failed to parse ciphertext"
    | some ciphertexts =>
        let sharedSecrets := KEMs.zip ciphertexts |>.zip privkey.data |>.map (fun ((kem, ct), privKeyChunk) =>
          match kem.decodePrivateKey privKeyChunk with
          | none => panic! "decode private key failure"
          | some innerPrivkey => kem.decapsulate innerPrivkey ct
        )
        (splitPRF hash sharedSecrets ciphertexts).val,

  encodePrivateKey := fun privkey =>
    privkey.data.foldl (fun acc key => acc ++ key) ByteArray.empty,

  decodePrivateKey := fun bytes =>
    let sizes : List Nat := KEMs.map (fun kem => kem.privateKeySize)
    match splitByteArrayIntoChunks bytes sizes with
    | none => none
    | some keys => some { data := keys },

  encodePublicKey := fun pubkey =>
    pubkey.data.foldl (fun acc key => acc ++ key) ByteArray.empty,

  decodePublicKey := fun bytes =>
    let sizes : List Nat := KEMs.map (fun kem => kem.publicKeySize)
    match splitByteArrayIntoChunks bytes sizes with
    | none => none
    | some keys => some { data := keys }
}

theorem combiner_lawful (name : String)
    (hash : ByteArray → { s : ByteArray // s.size = 32 })
    (KEMs : List KEM) (h : ∀ kem ∈ KEMs, LawfulKEM kem) :
    LawfulKEM (createKEMCombiner name hash KEMs) := by
      sorry


end CryptWalker.KEM.Combiner
