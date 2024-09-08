/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import Mathlib.Data.ByteArray
import CryptWalker.kem.kem

namespace CryptWalker.kem.combiner
open CryptWalker.kem.kem

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

def xorByteArrays (a b : ByteArray) : ByteArray :=
  if a.size ≠ b.size then
    panic! "xorByteArrays: ByteArrays must be of equal size"
  else
    ByteArray.mk (Array.zipWith a.data b.data fun x y => x ^^^ y)

def splitPRF (hash : ByteArray → ByteArray) (ss : List ByteArray) (ct : List ByteArray) : ByteArray :=
  if ss.length != ct.length then
    panic! "splitPRF failure: mismatched List lengths"
  else
    let bigCt : ByteArray := ct.foldl (fun acc blob => acc ++ blob) ByteArray.empty
    (ss.map (fun x => hash (x ++ bigCt))).foldl (fun acc h => xorByteArrays acc h) (ByteArray.mk (Array.mkArray hashSize 0))

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

def createKEMCombiner (name : String) (hash : ByteArray → ByteArray) (KEMs : List KEM) : KEM :=
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

  encapsulate := fun pubkey => do
    let mut sharedSecrets : List ByteArray := []
    let mut ciphertexts : List ByteArray := []
    let mut ciphertext : ByteArray := ByteArray.empty
    for (kem, pubKeyChunk) in KEMs.zip pubkey.data do
      match kem.decodePublicKey pubKeyChunk with
      | none => panic! "failed to decode pub key"
      | some pubkey =>
        let (ct, ss) ← kem.encapsulate pubkey
        sharedSecrets := sharedSecrets ++ [ss]
        ciphertexts := ciphertexts ++ [ct]
        ciphertext := ciphertext ++ ct
    pure (ciphertext, splitPRF hash sharedSecrets ciphertexts),

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
        splitPRF hash sharedSecrets ciphertexts

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

end CryptWalker.kem.combiner
