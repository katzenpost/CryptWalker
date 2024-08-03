
/- work-in-progress attempt to port this Haskell merkle tree to Lean
 https://github.com/kazu-yamamoto/hash-tree/blob/main/Data/HashTree/Internal.hs
-/

import Mathlib.Data.ByteArray
import Mathlib.Data.HashMap
import «CryptWalker».hash
import «CryptWalker».nat

structure Settings :=
  (hash0 : ByteArray)
  (hash1 : Nat → ByteArray)
  (hash2 : ByteArray → ByteArray → ByteArray)

def myhash0 : ByteArray := myhash (ByteArray.empty)

def mySettings : Settings := {
  hash0 := myhash0
  hash1 := fun x => myhash (ByteArray.mk #[0x00] ++ (natToBytes x)),
  hash2 := fun x y => myhash (ByteArray.mk #[0x01] ++ x ++ y),
}

inductive HashTree where
  | empty
  | leaf (hash : ByteArray)
  | node (hash : ByteArray) (leftTree : HashTree) (rightTree : HashTree)

instance : BEq ByteArray where
  beq a b := a.data = b.data

structure MerkleHashTrees :=
  (settings : Settings)
  (size : USize)
  (hashtrees : (Lean.HashMap Nat HashTree))
  (indices : (Lean.HashMap ByteArray Nat))
