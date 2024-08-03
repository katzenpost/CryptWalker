
/- work-in-progress attempt to port this Haskell merkle tree to Lean
 https://github.com/kazu-yamamoto/hash-tree/blob/main/Data/HashTree/Internal.hs
-/

import Mathlib.Data.ByteArray
import Mathlib.Data.HashMap
import «CryptWalker».hash
import «CryptWalker».nat

instance : BEq ByteArray where
  beq a b := a.data = b.data

def myhash0 : ByteArray := myhash (ByteArray.empty)

structure Settings  where
  hash0 : ByteArray := myhash (ByteArray.empty)
  hash1 : ByteArray → ByteArray := fun x => myhash (ByteArray.mk #[0x00] ++ x)
  hash2 : ByteArray → ByteArray → ByteArray := fun x y => myhash (ByteArray.mk #[0x01] ++ x ++ y)

abbrev Index := Nat

inductive HashTree where
  | empty
  | leaf (hash : ByteArray) (index : Nat) (value : ByteArray)
  | node (hash : ByteArray) (leftIndex : Nat) (rightIndex : Nat) (leftTree : HashTree) (rightTree : HashTree)

structure MerkleHashTrees :=
  (settings : Settings)
  (size : Nat)
  (hashtrees : (Lean.HashMap Nat HashTree))
  (indices : (Lean.HashMap ByteArray Nat))

/-! digest gets the current Merkle Tree hash value -/
def digest (treeSize : Nat) (tree : MerkleHashTrees) : Option ByteArray :=
  match Lean.HashMap.findEntry? tree.hashtrees treeSize with
  | .none => none
  | some (_, ht) =>
    match ht with
    | HashTree.empty => none
    | HashTree.leaf hash _ _ => some hash
    | HashTree.node hash _ _ _ _ => some hash

/-! currentHead returns the current Merkle Tree head -/
def currentHead (tree : MerkleHashTrees) : Option HashTree :=
  match Lean.HashMap.findEntry? tree.hashtrees tree.size with
  | .none => none
  | some (_, ht) => some ht

/-! info gets the root information of the Merkle Hash tree.
    A pair of the current size and the current Merkle Tree Hash is returned. -/
def info (tree : MerkleHashTrees) : (Nat × Option ByteArray) :=
  (tree.size, digest tree.size tree)

--def empty (settings : Settings) : MerkleHashTrees :=
--  MerkleHashTrees
