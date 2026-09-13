
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Combiner
import CryptWalker.Hash.Sha2

open CryptWalker.NIKE
open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter
open CryptWalker.Hash.Sha2

namespace CryptWalker.KEM


/-- SHA-256, retyped to `Vector UInt8 32`. -/
def sha256V (b : ByteArray) : Vector UInt8 32 :=
  let r := Sha256.hash b
  ⟨r.val.data, r.property⟩

/-- Big-endian `u32`, matching Go's `binary.BigEndian.PutUint32`. -/
def u32be (n : Nat) : ByteArray :=
  ⟨#[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]⟩

/-- A field under a big-endian 32-bit length prefix. -/
def lenPrefixed (b : ByteArray) : ByteArray := u32be b.size ++ b

/-- Domain-separation tag, identical to `sha256v1Label` in
`hpqc/kem/adapter/kem.go`. -/
def sha256v1Label : ByteArray := "kemadapter-sha256-v1".toUTF8

/-- The `sha256-v1` PRF:

```
SHA256(label || u32be(len(ss))       || ss
             || u32be(len(pkStatic)) || pkStatic
             || u32be(len(pkEph))    || pkEph)
```

Every variable-length field is length-prefixed, so the encoding is unambiguous
regardless of the NIKE's key sizes. This is a portable stand-in for hpqc's
deployed BLAKE2b XOF, not the deployed construction; it exists so that
implementations with SHA-256 but no BLAKE2b can still check shared vectors.

Defined only at `outLen = 32`, one SHA-256 digest. Go returns an error for any
other width; this returns zero-padding instead, since making it partial would
push an `Option` through `encapM`/`decapM` and their correctness proof for a
case no NIKE here reaches (X25519 has `sharedSecretSize = 32`). Callers must not
use it at another width. -/
def sha256v1Derive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let d := sha256V (sha256v1Label ++ lenPrefixed ss ++ lenPrefixed pkStatic ++ lenPrefixed pkEph)
  Vector.ofFn (fun i => if h : i.val < 32 then d[i.val]'h else 0)

def sha256v1PRF : Adapter.PRF where
  name   := "sha256-v1"
  derive := sha256v1Derive

/-- The Montgomery-ladder X25519 implementation, wrapped into a KEM. Registered under
`"x25519-ladder"`, matching `NIKE.Schemes`'s naming (see there for why the ladder implementation
carries the suffix and the group one doesn't). -/
def kemX25519Ladder : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.LadderScheme

/-- The group-formulation X25519 implementation, wrapped into a KEM. Registered under the bare
`"x25519"` name, matching `NIKE.Schemes`'s convention — the two NIKEs agree byte-for-byte
(`CryptWalker.NIKE.test`'s `testX25519GroupAgreesWithLadder`), so either can serve as *the*
`"x25519"` KEM; picking the group one here is purely for naming symmetry with `NIKE.Schemes`. -/
def kemX25519 : KEM := kemOfNike sha256v1PRF CryptWalker.NIKE.X25519.Scheme

/-! ## The `hpqc/kem/schemes` registry, ported

`hpqc/kem/schemes.All()` lists ~30 schemes (MLKEM768, sntrup, HQC, FrodoKEM, the Classic McEliece
family, X-Wing, and many hybrid combiners — see `hpqc/kem/schemes/schemes.go`); this project
ports `hpqc`'s one X25519 adapter twice over, once per X25519 implementation
(`kemX25519`/`kemX25519Ladder`) — `hpqc/kem/adapter`'s own `Scheme.Name()`
(`kem/adapter/kem.go:120`) just returns the wrapped NIKE's name (`a.nike.Name()`), so the
registered names are the same strings `NIKE.Schemes`'s registry uses — no collision, since Go
keeps `nike/schemes` and `kem/schemes` as two independent maps, and so does this port. (Earlier
this file exposed a bare `Schemes : List String := ["X25519"]`, wrong on both counts —
capitalized unlike `hpqc`'s own name, and not actually paired with a scheme.) -/

/-- One entry in the scheme registry: a scheme's canonical `hpqc` name, the actual implementation
`byName` should return for it, and the `prf`/`nike` it was built from — every KEM this project can
currently construct is `kemOfNike`-shaped (`kemOfNike` is the only KEM constructor in the codebase),
so `prf`/`nike` are required, not optional; a future non-adapter KEM would need to revisit this. -/
structure RegistryEntry where
  hpqcName : String
  scheme : KEM
  prf : Adapter.PRF
  nike : NIKE

def x25519LadderEntry : RegistryEntry :=
  { hpqcName := "x25519-ladder", scheme := kemX25519Ladder, prf := sha256v1PRF
    nike := X25519_montgomery_ladder.LadderScheme }

def x25519GroupEntry : RegistryEntry :=
  { hpqcName := "x25519", scheme := kemX25519, prf := sha256v1PRF
    nike := CryptWalker.NIKE.X25519.Scheme }

def registry : List RegistryEntry := [x25519LadderEntry, x25519GroupEntry]

/-- `hpqc/kem/schemes.ByName`, ported: case-insensitive lookup, `none` for any name not in
`registry` — which, unlike `hpqc`'s own registry, is most of `hpqc/kem/schemes.All()`: this
project has not ported the post-quantum KEMs or the hybrid combiners. -/
def byName (name : String) : Option KEM :=
  (registry.find? (·.hpqcName.toLower == name.toLower)).map (·.scheme)

/-- As `byName`, but returning the whole entry — needed wherever a caller must build a fresh
scheme instance rather than just call `KEM.encap`/`decap` on the registered one, since `KEM.KEM`
has no generic "derive a public key from a given private key" operation (only `generate`, which
samples a fresh keypair jointly): `Sphinx.KEMSphinx` needs the underlying `nike`'s own
`derivePublicKey` for that. -/
def adapterByName (name : String) : Option RegistryEntry :=
  registry.find? (·.hpqcName.toLower == name.toLower)

end CryptWalker.KEM
