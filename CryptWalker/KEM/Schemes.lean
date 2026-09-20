
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Combiner
import CryptWalker.KEM.MLKEM768
import CryptWalker.Hash.Sha2
import CryptWalker.Hash.Blake2b
import CryptWalker.MAC.HMAC
import CryptWalker.Util.Bytes

open CryptWalker.NIKE
open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter
open CryptWalker.Hash.Sha2
open CryptWalker.MAC.HMAC (hmacSha256)
open CryptWalker.Util.Bytes (ofVector toVecN)

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

/-- The `blake2b-xof` PRF: hpqc's deployed adapter configuration (`kem/adapter/kem.go`'s
`blake2bXOF`), now that `Hash.Blake2b` has BLAKE2Xb. `ss` keys the XOF directly only at exactly 32
bytes -- the only width any NIKE in this port produces -- matching Go's `len(ss) != 32` branch,
which otherwise collapses `ss` to 32 bytes via an unkeyed BLAKE2b-256 hash first.

`xof`'s `size` and `readLen` are two different quantities Go's `Derive` also keeps separate:
`size` (the XOF's configured length, baked into its parameter block) is `sharedKeySize` — here,
`outLen`, the width `Adapter.derive` calls this at — while `readLen` (how many bytes are actually
produced) is `ss.size`. Every NIKE here has `sharedSecretSize = publicKeySize`, so `outLen` and
`ss.size` coincide in practice, exactly the "wart" `Adapter.lean`'s module doc already notes; this
follows Go in keeping them as distinct arguments regardless. -/
def blake2bXOFDerive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let xofKey := if ss.size == 32 then ss else ofVector (CryptWalker.Hash.Blake2b.hash256 ss)
  toVecN outLen (CryptWalker.Hash.Blake2b.xof xofKey outLen ss.size (pkStatic ++ pkEph))

def blake2bXOFPRF : Adapter.PRF where
  name   := "blake2b-xof"
  derive := blake2bXOFDerive

/-- The Montgomery-ladder X25519 implementation, wrapped into a KEM. Registered under
`"x25519-ladder-kem"` — see the registry section below for why this diverges from `hpqc`'s own
naming. -/
def kemX25519Ladder : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.LadderScheme

/-- The group-formulation X25519 implementation, wrapped into a KEM. Registered under
`"x25519-kem"` — the two NIKEs agree byte-for-byte
(`CryptWalker.NIKE.test`'s `testX25519GroupAgreesWithLadder`), so either can serve as *the*
`"x25519-kem"` KEM; picking the group one here is purely for naming symmetry with
`NIKE.Schemes`'s own `x25519GroupEntry`. -/
def kemX25519 : KEM := kemOfNike sha256v1PRF CryptWalker.NIKE.X25519.Scheme

/-- The group-formulation X25519 implementation under the deployed `blake2b-xof` adapter PRF,
matching hpqc's own default (`adapter.FromNIKE`, `kem/schemes.go`'s registered `"MLKEM768-X25519"`
and the bare `"x25519"` KEM adapter entry) rather than `kemX25519`'s portable `sha256-v1` stand-in.
Not added to `registry` below: every entry there is named after an `hpqc` scheme name, and hpqc
has no separately-named scheme for "X25519 adapter, blake2b-xof PRF" (its bare adapter entry over
X25519 already means this) — `kemX25519` fills that registry slot instead, for the reason its own
doc comment gives, and callers that specifically want the deployed PRF (the hybrid combiner
vectors below) use this value directly. -/
def kemX25519Blake2b : KEM := kemOfNike blake2bXOFPRF CryptWalker.NIKE.X25519.Scheme

/-! ## The `hpqc/kem/schemes` registry, ported (names deliberately diverge from `hpqc`)

`hpqc/kem/schemes.All()` lists ~30 schemes (MLKEM768, sntrup, HQC, FrodoKEM, the Classic McEliece
family, X-Wing, and many hybrid combiners — see `hpqc/kem/schemes/schemes.go`); this project
ports `hpqc`'s one X25519 adapter twice over, once per X25519 implementation
(`kemX25519`/`kemX25519Ladder`). `hpqc/kem/adapter`'s own `Scheme.Name()`
(`kem/adapter/kem.go:120`) just returns the wrapped NIKE's name unchanged (`a.nike.Name()`), so
in `hpqc` a KEM-adapter scheme and its underlying NIKE share one string — harmless there only
because `nike/schemes` and `kem/schemes` are two independent Go maps. This port's `NIKE.registry`
and `KEM.registry` get merged into one flat `Sphinx.Schemes.schemeNames` list
(`schemes.lean`), where that collision would be real and confusing (two different entries named
`"x25519"`, one NIKE-backed and one KEM-backed). So, unlike `hpqc`, every KEM-adapter entry here
carries an explicit `-kem` suffix its underlying NIKE entry lacks — a deliberate naming choice,
not a port of anything `hpqc` does. (Earlier this file exposed a bare
`Schemes : List String := ["X25519"]`, wrong on both counts — capitalized unlike `hpqc`'s own
name, and not actually paired with a scheme.) -/

/-- One entry in the scheme registry: a scheme's registry name paired with the actual
implementation `byName` should return for it. Named `hpqcName` for parallelism with
`NIKE.RegistryEntry`, though the KEM-side value is this port's own `-kem`-suffixed name, not
`hpqc`'s (see the registry section above). `KEM.KEM` carries everything a caller (including
`Sphinx.KEMSphinx`) needs directly — `derivePublicKey`, `stateFromSeed` — so, unlike an earlier
version of this structure, there is no need to also carry the `prf`/`nike` a `kemOfNike`-built
scheme happens to be made from; that stays an internal detail of `Adapter.kemOfNike`. -/
structure RegistryEntry where
  hpqcName : String
  scheme : KEM

def x25519LadderEntry : RegistryEntry := { hpqcName := "x25519-ladder-kem", scheme := kemX25519Ladder }

def x25519GroupEntry : RegistryEntry := { hpqcName := "x25519-kem", scheme := kemX25519 }

/-- ML-KEM-768 (FIPS 203), post-quantum — `CryptWalker.KEM.MLKEM768.kemMLKEM768`. Unlike the two
X25519 entries above (Diffie-Hellman-based, so `KEM.Reliable` stays at its trivial default), this
one's `Reliable` is a real, non-trivial condition (see `MLKEM768.lean`'s module doc) — any caller
building a `KEMSphinxScheme` from this entry must discharge it, not just `trivial`. -/
def mlkem768Entry : RegistryEntry :=
  { hpqcName := "mlkem768-kem", scheme := CryptWalker.KEM.MLKEM768.kemMLKEM768 }

/-! ## Hybrid: X25519 + ML-KEM-768, via the generic split-PRF combiner

hpqc's `kem/schemes` registers exactly this pairing twice, via two different mechanisms
(`schemes.go`): `"Xwing"`, the fixed, non-generic construction from draft-connolly-cfrg-xwing (a
single SHA3-256 hash over both raw secrets and both public keys, no split-PRF, no sub-KEM
agility); and `"MLKEM768-X25519"`, built via hpqc's *generic* `kem/combiner` — the same
`Combiner.combineKEM` this project already has. hpqc's own comment on that second entry: "If Xwing
is not the PQ Hybrid KEM you are looking for then we recommend using our secure generic KEM
combiner." This is that one, not X-Wing. -/

/-- `Combiner.PRF`, instantiated with BLAKE2b-256 -- matching hpqc's deployed combiner
(`kem/combiner/split_prf.go`) exactly: an unkeyed BLAKE2b-256 hash for key derivation, and a keyed
BLAKE2b-256 hash for the per-component PRF. -/
def blake2b256CombinerPRF : Combiner.PRF where
  hash  := CryptWalker.Hash.Blake2b.hash256
  keyed := fun key msg => CryptWalker.Hash.Blake2b.hash256Keyed (Combiner.toBytes key) msg

/-- X25519 combined with ML-KEM-768 via `Combiner.combineKEM` — IND-CCA2 as long as *at least
one* component is (Giacon, Heuer & Poettering, https://eprint.iacr.org/2018/024.pdf, Theorem 1).
`Reliable` is `combineKEM`'s generic `k₀.Reliable s.1 ∧ ReliableN [k₁] s.2` — trivial on the X25519
half, ML-KEM-768's genuine noise-dependent condition on the other; any caller building a
`KEMSphinxScheme` from this entry must still discharge that, exactly as for `mlkem768Entry` alone.

Uses `MLKEM768.kemMLKEM768Seed`, not the plain `mlkem768Entry`'s `kemMLKEM768` — the private-key
wire format needs to match Go's `crypto/mlkem` (`ek ‖ d ‖ z`, 1248 bytes) for real KEM-Sphinx
packets built by katzenpost to be decodable here at all; `kemMLKEM768`'s FIPS 203 *expanded*
private-key format (2400 bytes) cannot represent Go's compact one (see `MLKEM768.lean`'s module
doc on `kemMLKEM768Seed`). -/
def kemMLKEM768X25519 : KEM :=
  Combiner.combineKEM blake2b256CombinerPRF kemX25519 [CryptWalker.KEM.MLKEM768.kemMLKEM768Seed]

def mlkem768X25519Entry : RegistryEntry :=
  { hpqcName := "mlkem768-x25519-kem", scheme := kemMLKEM768X25519 }

def registry : List RegistryEntry :=
  [x25519LadderEntry, x25519GroupEntry, mlkem768Entry, mlkem768X25519Entry]

/-- `hpqc/kem/schemes.ByName`, ported: case-insensitive lookup, `none` for any name not in
`registry` — which, unlike `hpqc`'s own registry, is most of `hpqc/kem/schemes.All()`: this
project has not ported the post-quantum KEMs or the hybrid combiners. -/
def byName (name : String) : Option KEM :=
  (registry.find? (·.hpqcName.toLower == name.toLower)).map (·.scheme)

end CryptWalker.KEM
