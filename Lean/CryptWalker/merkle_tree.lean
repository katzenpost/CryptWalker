
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
structure Settings (α : Type) [Hashable α] where
  hash0 : ByteArray
  hash1 : α → ByteArray
  hash2 : ByteArray → ByteArray → ByteArray

def defaultByteArraySettings : Settings ByteArray :=
  { hash0 := myhash (ByteArray.empty),
    hash1 :=  fun x => myhash (ByteArray.mk #[0x00] ++ x),
    hash2 := fun x y => myhash (ByteArray.mk #[0x01] ++ x ++ y) }

inductive HashTree (α : Type) where
  | empty (hash : ByteArray)
  | leaf (hash : ByteArray) (index : Nat) (value : α)
  | node (hash : ByteArray) (leftIndex : Nat) (rightIndex : Nat) (leftTree : HashTree α) (rightTree : HashTree α)
deriving BEq

instance {α : Type} : Inhabited (HashTree α) where
  default := HashTree.empty (ByteArray.mk #[])

structure MerkleHashTrees (α : Type) [Hashable α] :=
  (settings : Settings α)
  (size : Nat)
  (hashtrees : (Lean.HashMap Nat (HashTree α)))
  (indices : (Lean.HashMap ByteArray Nat))

/-! digest gets the current Merkle Tree hash value -/
def digest (α : Type) [Hashable α] (treeSize : Nat) (tree : MerkleHashTrees α) : ByteArray :=
  match Lean.HashMap.findEntry? tree.hashtrees treeSize with
  | .none => panic! "failed to find entry in hash tree"
  | some (_, ht) =>
    match ht with
    | HashTree.empty hash => hash
    | HashTree.leaf hash _ _ => hash
    | HashTree.node hash _ _ _ _ => hash

def index (α : Type) [Hashable α] (tree : MerkleHashTrees α) (hash : ByteArray) : Nat :=
  match Lean.HashMap.findEntry? tree.indices hash with
  | some n => n.snd
  | none => panic! "failed to find tree index"

/-! currentHead returns the current Merkle Tree head -/
def currentHead (α : Type) [Hashable α] (tree : MerkleHashTrees α) : Option (HashTree α):=
  match Lean.HashMap.findEntry? tree.hashtrees tree.size with
  | .none => none
  | some (_, ht) => some ht

/-! info gets the root information of the Merkle Hash tree.
    A pair of the current size and the current Merkle Tree Hash is returned. -/
def info (α : Type) [Hashable α] (tree : MerkleHashTrees α) : (Nat × Option ByteArray) :=
  (tree.size, digest α tree.size tree)

/-! empty creates an empty 'MerkleHashTrees'. -/
def empty (α : Type) [Hashable α] (settings : Settings α) : MerkleHashTrees α :=
  MerkleHashTrees.mk settings 0 (Lean.mkHashMap) (Lean.mkHashMap)

/-! hashValue returns the hash value for the given HashTree. -/
def hashValue (α : Type) [Hashable α] (tree : HashTree α) : ByteArray :=
  match tree with
  | .empty hash => hash
  | .leaf hash _ _ => hash
  | .node hash _ _ _ _=> hash

def rightIndex (α : Type) (tree : HashTree α) : Nat :=
  match tree with
  | HashTree.node _ _ rightIndex _ _ => rightIndex
  | _ => panic! "not a node"

def isPowerOf2 (n : Nat) : Bool :=
  (n &&& (n - 1)) == 0

/-! insert returns a new hash tree with the newLeaf hash tree inserted into the given tree. -/
def insert (α : Type) [Hashable α] (tree : HashTree α) (hash : ByteArray) (newLeaf : HashTree α) (settings : Settings α) (size : Nat) : HashTree α :=
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
def add (α : Type) [Hashable α] (inp : α) (tree : MerkleHashTrees α) : MerkleHashTrees α :=
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
def fromList (α : Type) [Hashable α] (settings : Settings α) (xs : List α) : MerkleHashTrees α :=
  xs.foldl (fun acc x => add α x acc) (empty α settings)

structure InclusionProof where
  index : Nat := 0
  treeSize : Nat := 1
  inclusion : List ByteArray := []
deriving BEq

instance : Inhabited InclusionProof where
  default := { index := 0, treeSize := 0, inclusion := [] }

def path (α : Type) [Hashable α] (index : Nat) (tree : HashTree α) : List ByteArray :=
  match tree with
  | HashTree.node _ _ _ l r =>
    if index <= rightIndex α l then hashValue α r :: path α index l else hashValue α l :: path α index r
  | _ => []

def sizeTree (α : Type) [Hashable α] (tree : MerkleHashTrees α) (treeSize : Nat) : (HashTree α) :=
  match tree.hashtrees.find? treeSize with
  | none => panic! "failed to find hash tree entry"
  | .some x => x

def genarateInclusionProof (α : Type) [Hashable α] (targetHash : ByteArray) (treeSize : Nat) (tree : MerkleHashTrees α) : Option InclusionProof :=
  let ht : HashTree α := sizeTree α tree treeSize
  let i := index α tree targetHash
  if i < treeSize then
    let digests := List.reverse $ path α i ht
    some { index := i, treeSize := treeSize, inclusion := digests }
  else
    none

def shiftR1 (p : Nat × Nat) : Nat × Nat :=
  (p.fst >>> 1, p.snd >>> 1)

def untilSet (fst snd : Nat) : Nat × Nat :=
  if fst % 2 == 0 && fst > 0 then untilSet (fst >>> 1) (snd >>> 1) else (fst, snd)
  termination_by fst
  decreasing_by
  sorry

def verifyInclusionProof (α : Type) [Hashable α] (settings : Settings α) (leafHash : ByteArray) (rootHash : ByteArray) (proof : InclusionProof) : Bool :=
  if proof.index >= proof.treeSize then false else
    let rec verify (index treeSize : Nat) (currentHash : ByteArray) (proof' : List ByteArray) : Bool :=
      match index, treeSize, proof' with
      | _, 0, _ => false
      | _, _, [] => treeSize == 0 && currentHash == rootHash
      | index, treeSize, p :: ps =>
        if index % 2 == 1 || index == treeSize then
          let currentHash' := settings.hash2 p currentHash
          let fsn' := shiftR1 $ untilSet index treeSize
          verify fsn'.fst fsn'.snd currentHash' ps
        else
          let currentHash' := settings.hash2 currentHash p
          let fsn' := shiftR1 (index, treeSize)
          verify fsn'.fst fsn'.snd currentHash' ps
    verify proof.index (proof.treeSize - 1) leafHash proof.inclusion
