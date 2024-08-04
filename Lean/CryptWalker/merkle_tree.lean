
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

/-! Settings for Merkle Hash Trees. -/
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

/-! empty creates an empty 'MerkleHashTrees'. -/
def empty (settings : Settings) : MerkleHashTrees :=
  MerkleHashTrees.mk settings 0 (Lean.mkHashMap) (Lean.mkHashMap)

/-! hashValue returns the hash value for the given HashTree. -/
def hashValue (tree : HashTree) : Option ByteArray :=
  match tree with
  | .empty => none
  | .leaf hash _ _ => some hash
  | .node hash _ _ _ _=> some hash

def isPowerOf2 (n : Nat) : Bool :=
  (n &&& (n - 1)) == 0

/-! insert returns a new hash tree with the newLeaf hash tree inserted into the given tree. -/
def insert (tree : HashTree) (hash : ByteArray) (newLeaf : HashTree) (settings : Settings) (size : Nat) : HashTree :=
  match tree with
  | HashTree.empty =>
    newLeaf
  | HashTree.leaf h idx value =>
    HashTree.node (settings.hash2 h hash) idx (idx + 1) tree newLeaf
  | HashTree.node h leftIdx rightIdx leftTree rightTree =>
    if isPowerOf2 (size + 1) then
      HashTree.node (settings.hash2 h hash) leftIdx (rightIdx + 1) tree newLeaf
    else
      let newRight := insert rightTree hash newLeaf settings size
      let leftHash := match leftTree with
        | .empty => panic! "impossible error"
        | .leaf hash _ _ => hash
        | .node hash _ _ _ _ => hash
        let rightHash := match rightTree with
        | .empty => panic! "impossible error"
        | .leaf hash _ _ => hash
        | .node hash _ _ _ _ => hash
      HashTree.node (settings.hash2 leftHash rightHash) leftIdx (rightIdx + 1) leftTree newRight

/-! add, adds the given input into the tree, returning the new tree. -/
def add (inp : ByteArray) (tree : MerkleHashTrees) : MerkleHashTrees :=
  let hx := tree.settings.hash1 inp
  if tree.indices.contains hx then
    tree
  else
    let newSize := tree.size + 1
    let newLeaf := HashTree.leaf hx newSize inp
    let newHt := match tree.hashtrees.find? tree.size with
      | some ht => insert ht hx newLeaf tree.settings tree.size
      | none => newLeaf -- should not happen
    let newHashTrees := tree.hashtrees.insert newSize newHt
    { tree with size := newSize, hashtrees := newHashTrees, indices := tree.indices.insert hx newSize }

/-! fromList inserts a list of input items into the tree. -/
def fromList (settings : Settings) (xs : List ByteArray) : MerkleHashTrees :=
  xs.foldl (fun acc x => add x acc) (empty settings)
