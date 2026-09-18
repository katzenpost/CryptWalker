import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE

open CryptWalker.NIKE.NIKE

namespace CryptWalker.NIKE

/-! # The X25519 schemes

Two implementations of the same exchange, kept side by side on purpose.

`X25519Scheme` is the group formulation: public keys are points on Curve25519 and the group
action is Mathlib's scalar multiplication, so `commutes` is proved rather than assumed.

`X25519LadderScheme` is the byte-level Montgomery ladder of RFC 7748. It is the faster and more
conventional one, but it has to take `curve25519_commutes` and `derivePub_safe` as axioms,
because it computes over byte strings with no group structure to appeal to.

They differ in two visible ways. Public keys encode differently — 65 bytes `0x04 ‖ x ‖ y` for
the group version, 32-byte u-coordinates for the ladder — and their `Safe` predicates differ:
the ladder rejects the small-order points, while in the group scalar multiplication is total
and there is nothing to reject. -/

def X25519Scheme : NIKE := X25519.Scheme

def X25519LadderScheme : NIKE := X25519_montgomery_ladder.LadderScheme

def implementations : List NIKE :=
  [
    X25519Scheme,
    X25519LadderScheme
  ]

/-! ## The `hpqc/nike/schemes` registry, ported

`NIKE.name` above (`"X25519-group"`/`"X25519-ladder"`) disambiguates *this project's own* two
X25519 implementations; it is not the identity `hpqc/nike/schemes.ByName` keys on, which names
the *cryptographic scheme* independent of which of this project's implementations computes it.
`hpqc/nike/schemes.All()` lists ~12 schemes (`x25519`, `x448`, `ctidh511/512/1024/2048`, and
several CTIDH×X25519/X448 hybrids — see `hpqc/nike/schemes/schemes.go`); this project ports
exactly one *cryptographic scheme*, X25519, but registers both of its implementations here under
their own names — `"x25519-ladder"` for `X25519LadderScheme`, `"x25519"` for `X25519Scheme` —
rather than picking one to squat on `hpqc`'s own name (`hpqc/nike/x25519/ecdh.go`'s
`Name() string { return "x25519" }`) and hiding the other. -/

/-- One entry in the scheme registry: a scheme's canonical `hpqc` name paired with the actual
implementation `byName` should return for it. -/
structure RegistryEntry where
  hpqcName : String
  scheme : NIKE

/-- The byte-level RFC 7748 implementation — the one that matches wire format, checked against
`sphinx_vectors.json`. Named distinctly from plain `"x25519"` so a caller must ask for it by name
rather than get it as a hidden default; see `x25519GroupEntry` for the other implementation. -/
def x25519LadderEntry : RegistryEntry := { hpqcName := "x25519-ladder", scheme := X25519LadderScheme }

/-- The Weierstrass-point formulation, whose `commutes` is proved algebraically rather than
assumed — but whose connection to the actual RFC 7748 byte encoding runs through
`curve25519_commutes`, an axiom, not a checked fact. Not verified against `sphinx_vectors.json`;
callers building an actual Sphinx packet almost certainly want `x25519LadderEntry` instead. -/
def x25519GroupEntry : RegistryEntry := { hpqcName := "x25519", scheme := X25519Scheme }

def registry : List RegistryEntry := [x25519LadderEntry, x25519GroupEntry]

/-- `hpqc/nike/schemes.ByName`, ported: case-insensitive lookup (Go's own `ByName` lower-cases
both sides), `none` for any name not in `registry` — which, unlike `hpqc`'s own registry, is most
of `hpqc/nike/schemes.All()`: this project has not ported CTIDH or the hybrid combiners. -/
def byName (name : String) : Option NIKE :=
  (registry.find? (·.hpqcName.toLower == name.toLower)).map (·.scheme)

end CryptWalker.NIKE
