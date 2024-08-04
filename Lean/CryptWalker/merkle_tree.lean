
/- work-in-progress attempt to port this Haskell merkle tree to Lean
 https://github.com/kazu-yamamoto/hash-tree/blob/main/Data/HashTree/Internal.hs
-/

import Mathlib.Data.ByteArray
import Mathlib.Data.HashMap
import «CryptWalker».hash
import «CryptWalker».nat

instance : BEq ByteArray where
  beq a b := a.data = b.data

/-! Settings for Merkle Hash Trees. -/
structure Settings (α : Type) where
  hash0 : ByteArray
  hash1 : α → ByteArray
  hash2 : ByteArray → ByteArray → ByteArray

/-
myhash (ByteArray.empty)
fun x => myhash (ByteArray.mk #[0x00] ++ x)
fun x y => myhash (ByteArray.mk #[0x01] ++ x ++ y)
-/

inductive HashTree (α : Type) where
  | empty (hash : ByteArray)
  | leaf (hash : ByteArray) (index : Nat) (value : α)
  | node (hash : ByteArray) (leftIndex : Nat) (rightIndex : Nat) (leftTree : HashTree α) (rightTree : HashTree α)
deriving BEq

structure MerkleHashTrees (α : Type) :=
  (settings : Settings α)
  (size : Nat)
  (hashtrees : (Lean.HashMap Nat (HashTree α)))
  (indices : (Lean.HashMap ByteArray Nat))

/-! digest gets the current Merkle Tree hash value -/
def digest (α : Type) (treeSize : Nat) (tree : MerkleHashTrees α) : Option ByteArray :=
  match Lean.HashMap.findEntry? tree.hashtrees treeSize with
  | .none => none
  | some (_, ht) =>
    match ht with
    | HashTree.empty hash => some hash
    | HashTree.leaf hash _ _ => some hash
    | HashTree.node hash _ _ _ _ => some hash

/-! currentHead returns the current Merkle Tree head -/
def currentHead (α : Type) (tree : MerkleHashTrees α) : Option (HashTree α):=
  match Lean.HashMap.findEntry? tree.hashtrees tree.size with
  | .none => none
  | some (_, ht) => some ht

/-! info gets the root information of the Merkle Hash tree.
    A pair of the current size and the current Merkle Tree Hash is returned. -/
def info (α : Type) (tree : MerkleHashTrees α) : (Nat × Option ByteArray) :=
  (tree.size, digest α tree.size tree)


/-! empty creates an empty 'MerkleHashTrees'. -/
def empty (α : Type) (settings : Settings α) : MerkleHashTrees α :=
  MerkleHashTrees.mk settings 0 (Lean.mkHashMap) (Lean.mkHashMap)

/-! hashValue returns the hash value for the given HashTree. -/
def hashValue (α : Type) (tree : HashTree α) : ByteArray :=
  match tree with
  | .empty hash => hash
  | .leaf hash _ _ => hash
  | .node hash _ _ _ _=> hash

def isPowerOf2 (n : Nat) : Bool :=
  (n &&& (n - 1)) == 0

/-! insert returns a new hash tree with the newLeaf hash tree inserted into the given tree. -/
def insert (α : Type) (tree : HashTree α) (hash : ByteArray) (newLeaf : HashTree α) (settings : Settings α) (size : Nat) : HashTree α :=
  match tree with
  | HashTree.empty _ =>
    newLeaf
  | HashTree.leaf h idx _value =>
    HashTree.node (settings.hash2 h hash) idx (idx + 1) tree newLeaf
  | HashTree.node h leftIdx rightIdx leftTree rightTree =>
    if isPowerOf2 (size + 1) then
      HashTree.node (settings.hash2 h hash) leftIdx (rightIdx + 1) tree newLeaf
    else
      let newRight := insert α rightTree hash newLeaf settings size
      let leftHash := hashValue α leftTree
      let rightHash := hashValue α rightTree
      HashTree.node (settings.hash2 leftHash rightHash) leftIdx (rightIdx + 1) leftTree newRight

/-! add, adds the given input into the tree, returning the new tree. -/
def add (α : Type) (inp : α) (tree : MerkleHashTrees α) : MerkleHashTrees α :=
  let hx := tree.settings.hash1 inp
  if tree.indices.contains hx then
    tree
  else
    let newSize := tree.size + 1
    let newLeaf := HashTree.leaf hx newSize inp
    let newHt := match tree.hashtrees.find? tree.size with
      | some ht => insert α ht hx newLeaf tree.settings tree.size
      | none => newLeaf -- should not happen
    let newHashTrees := tree.hashtrees.insert newSize newHt
    { tree with size := newSize, hashtrees := newHashTrees, indices := tree.indices.insert hx newSize }

/-! fromList inserts a list of input items into the tree. -/
def fromList (α : Type) (settings : Settings α) (xs : List α) : MerkleHashTrees α :=
  xs.foldl (fun acc x => add α x acc) (empty α settings)
