/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # A map that keeps insertion order

Setting a present key replaces its value in place; setting a new key appends it. -/

namespace CryptWalker.GroupChat.Member

structure Dict (K V : Type) where
  pairs : List (K × V)
  deriving Inhabited, DecidableEq

namespace Dict

variable {K V : Type} [DecidableEq K]

def empty : Dict K V := ⟨[]⟩

instance : EmptyCollection (Dict K V) := ⟨empty⟩

def get? (d : Dict K V) (k : K) : Option V := (d.pairs.find? (·.1 = k)).map (·.2)

def getD (d : Dict K V) (k : K) (v : V) : V := (d.get? k).getD v

def contains (d : Dict K V) (k : K) : Bool := (d.get? k).isSome

def set (d : Dict K V) (k : K) (v : V) : Dict K V :=
  if d.contains k then ⟨d.pairs.map fun p => if p.1 = k then (k, v) else p⟩
  else ⟨d.pairs ++ [(k, v)]⟩

/-- Set `k` only if it is absent. -/
def setDefault (d : Dict K V) (k : K) (v : V) : Dict K V := if d.contains k then d else d.set k v

def modify (d : Dict K V) (k : K) (f : V → V) : Dict K V :=
  match d.get? k with
  | some v => d.set k (f v)
  | none => d

def erase (d : Dict K V) (k : K) : Dict K V := ⟨d.pairs.filter (·.1 ≠ k)⟩

def keys (d : Dict K V) : List K := d.pairs.map (·.1)

def values (d : Dict K V) : List V := d.pairs.map (·.2)

def size (d : Dict K V) : Nat := d.pairs.length

def filter (d : Dict K V) (p : K → V → Bool) : Dict K V := ⟨d.pairs.filter fun e => p e.1 e.2⟩

def mapValues {W : Type} (d : Dict K V) (f : V → W) : Dict K W := ⟨d.pairs.map fun e => (e.1, f e.2)⟩

/-- Build a map from pairs in order; a later value for a key replaces an earlier one in place. -/
def ofList (l : List (K × V)) : Dict K V := l.foldl (fun d e => d.set e.1 e.2) empty

end Dict

end CryptWalker.GroupChat.Member
