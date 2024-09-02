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
    panic! "ByteArrays must be of equal size"
  else
    ByteArray.mk (Array.zipWith a.data b.data fun x y => x ^^^ y)

def splitPRF (hash : ByteArray → ByteArray) (ss : List ByteArray) (ct : List ByteArray) : ByteArray :=
  if ss.length != ct.length then
    panic! "splitPRF failure: mismatched List lengths"
  else
    let bigCt : ByteArray := ct.foldl (fun acc blob => acc ++ blob) ByteArray.empty
    (ss.map (fun x => hash (x ++ bigCt))).foldl (fun acc h => xorByteArrays acc h) (ByteArray.mkEmpty hashSize)

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


structure Combiner where
  hash : ByteArray → ByteArray
  KEMs : List KEM

instance (combiner : Combiner) (name : String) : KEM where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  privateKeySize := combiner.KEMs.foldl (fun acc x => acc + x.privateKeySize) 0
  publicKeySize := combiner.KEMs.foldl (fun acc x => acc + x.publicKeySize) 0
  ciphertextSize := combiner.KEMs.foldl (fun acc x => acc + x.ciphertextSize) 0

  name : String := name

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let mut pubkeyData : List ByteArray := []
    let mut privkeyData : List ByteArray := []
    for kem in combiner.KEMs do
      let (newpubkey, newprivkey) ← kem.generateKeyPair
      pubkeyData := pubkeyData ++ [kem.encodePublicKey newpubkey]
      privkeyData := privkeyData ++ [kem.encodePrivateKey newprivkey]
    pure ({ data := pubkeyData }, { data := privkeyData })

  encapsulate : PublicKey → IO (ByteArray × ByteArray) := fun pubkey => do
    let mut sharedSecrets : List ByteArray := []
    let mut ciphertexts : List ByteArray := []
    let mut ciphertext : ByteArray := ByteArray.mkEmpty 0
    for (kem, pubKeyChunk) in combiner.KEMs.zip pubkey.data do
      match kem.decodePublicKey pubKeyChunk with
      | none => panic! "failed to decode pub key"
      | some pubkey =>
        let (ct, ss) ← kem.encapsulate pubkey
        sharedSecrets := sharedSecrets ++ [ss]
        ciphertexts := ciphertexts ++ [ct]
        ciphertext := ciphertext ++ ct
    pure (ciphertext, splitPRF combiner.hash sharedSecrets ciphertexts)

  decapsulate : PrivateKey → ByteArray → ByteArray := fun privkey ciphertext =>
    let sizes : List Nat := combiner.KEMs.foldl (fun acc x => acc ++ [x.ciphertextSize]) []
    match splitByteArrayIntoChunks ciphertext sizes with
    | none => panic! "failed to parse ciphertext"
    | some ciphertexts =>
        let pairs := List.zip combiner.KEMs ciphertexts
        let pairs3 := List.zip pairs privkey.data
        let sharedSecrets : List ByteArray := pairs3.map (fun x =>
          match x.fst.fst.decodePrivateKey x.fst.snd with
          | none => panic! "decode private key failure"
          | some innerPrivkey =>
            x.fst.fst.decapsulate innerPrivkey x.fst.snd
        )
      splitPRF combiner.hash sharedSecrets ciphertexts

  encodePrivateKey : PrivateKey → ByteArray := fun privkey =>
    privkey.data.foldl (fun acc key => acc ++ key) ByteArray.empty

  decodePrivateKey : ByteArray → Option PrivateKey := fun bytes =>
    let sizes : List Nat := combiner.KEMs.map (fun kem => kem.privateKeySize)
    match splitByteArrayIntoChunks bytes sizes with
    | none => none
    | some keys => some { data := keys }

  encodePublicKey : PublicKey → ByteArray := fun pubkey =>
    pubkey.data.foldl (fun acc key => acc ++ key) ByteArray.empty

  decodePublicKey : ByteArray → Option PublicKey := fun bytes =>
    let sizes : List Nat := combiner.KEMs.map (fun kem => kem.publicKeySize)
    match splitByteArrayIntoChunks bytes sizes with
    | none => none
    | some keys => some { data := keys }

end CryptWalker.kem.combiner
