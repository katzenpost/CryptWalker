import Cryptlib.Primitives.NIKE.X25519_montgomery_ladder
import Cryptlib.Primitives.NIKE.X25519
import Cryptlib.Primitives.NIKE.NIKE

open Cryptlib.Primitives.NIKE.NIKE

namespace Cryptlib.Primitives.NIKE

/-! # The X25519 schemes

`X25519Scheme` computes in the curve group, so `commutes` is proved. `X25519LadderScheme` and
`X25519FeScheme` are RFC 7748 Montgomery ladders and take commutativity and safety as axioms. -/

def X25519Scheme : NIKE := X25519.Scheme

def X25519LadderScheme : NIKE := X25519_montgomery_ladder.LadderScheme

/-- The Montgomery ladder on `Field25519` limbs. -/
def X25519FeScheme : NIKE := X25519_montgomery_ladder.FeScheme

def implementations : List NIKE :=
  [
    X25519Scheme,
    X25519LadderScheme,
    X25519FeScheme
  ]

/-! ## Registry by canonical scheme name -/

/-- A canonical scheme name and its implementation. -/
structure RegistryEntry where
  hpqcName : String
  scheme : NIKE

def x25519LadderEntry : RegistryEntry := { hpqcName := "x25519-ladder", scheme := X25519LadderScheme }

def x25519GroupEntry : RegistryEntry := { hpqcName := "x25519-group", scheme := X25519Scheme }

def x25519FeEntry : RegistryEntry := { hpqcName := "x25519", scheme := X25519FeScheme }

def registry : List RegistryEntry := [x25519FeEntry, x25519LadderEntry, x25519GroupEntry]

/-- Case-insensitive lookup by scheme name. -/
def byName (name : String) : Option NIKE :=
  (registry.find? (·.hpqcName.toLower == name.toLower)).map (·.scheme)

end Cryptlib.Primitives.NIKE
