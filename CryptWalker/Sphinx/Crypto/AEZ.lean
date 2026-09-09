/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AES

namespace CryptWalker.Sphinx.Crypto.AEZ

open CryptWalker.Cipher.AES (subBytes shiftRows mixColumns)

/-! # AEZ v5, restricted to Sphinx's exact usage

`crypto.SPRPEncrypt`/`crypto.SPRPDecrypt` (`katzenpost/core/sphinx/internal/crypto/crypto.go`)
call `gitlab.com/yawning/aez.git`'s `Encrypt`/`Decrypt` with `additionalData = nil`, `tau = 0`,
a 48-byte key (`SPRPKeyLength`), and a 16-byte nonce (`SPRPIVLength`) — i.e. AEZ used in pure
SPRP mode: a length-preserving strong pseudorandom permutation, no AEZ-native authentication
tag, no associated data. This file ports exactly that usage, not general AEZ-AEAD:

* **No key extraction.** `aez.go`'s `extract` only hashes the key with BLAKE2b when it isn't
  already exactly the 48-byte "extracted key" size; Sphinx's `SPRPKeyLength` is 48, so that
  branch never fires here, and this file simply requires a 48-byte key.
* **No associated data.** The AD-hashing loop in `aezHash` (`for k, p := range ad`) is absent;
  Sphinx never passes AD.
* **No `aezPRF`.** It is only reachable when the plaintext is empty *and* `tau > 0`; with
  `tau = 0` the empty-plaintext case is simply an empty ciphertext, so `aezPRF` is unneeded.

Everything else — `doubleBlock`'s GF(2¹²⁸) doubling, the `eState` key schedule, `AES4`/`AES10`,
`aezHash`'s nonce-hashing loop, `aezTiny` and `aezCore` — is a direct, line-by-line port of the
upstream reference (`aez_ref.go`/`round_vartime.go`'s literal T-table-free round function, i.e.
plain SubBytes/ShiftRows/MixColumns/AddRoundKey composed `rounds` times with **no** initial
whitening beyond what `AES4`/`AES10`'s caller-supplied `j`,`i`,`l` XOR already provides, and
**no** skipped-MixColumns final round the way AES-256 proper has) — reusing `Cipher.AES`'s
`subBytes`/`shiftRows`/`mixColumns` round primitives, since AEZ's round function is built from
the same three steps, just under a different, fixed-length key schedule.

Deferred per the project's vectors-first pass: no laws are stated about this module. Checked
against `sprp_aez.json`, covering both the `aezTiny` (<32B) and `aezCore` (≥32B) code paths. -/

abbrev Block := Array UInt8 -- always length 16 here; not tracked in the type, matching this
                             -- module's Go original, which is not proof-carrying either.

private def zero16 : Block := Array.replicate 16 0

private def xor16 (a b : Block) : Block := Array.ofFn fun i : Fin 16 => a[i.val]! ^^^ b[i.val]!

private def xor4 (a b c d : Block) : Block :=
  Array.ofFn fun i : Fin 16 => a[i.val]! ^^^ b[i.val]! ^^^ c[i.val]! ^^^ d[i.val]!

/-- GF(2¹²⁸) doubling: shift the 16-byte big-endian value left by one bit, reducing by the
primitive polynomial `x¹²⁸+x⁷+x²+x+1` (conditionally XOR `0x87` into the low byte) when the top
bit overflows. -/
def doubleBlock (p : Block) : Block := Id.run do
  let mut out : Block := zero16
  for i in [0:15] do
    out := out.set! i ((p[i]! <<< 1) ||| (p[i+1]! >>> 7))
  let top := p[0]! >>> 7
  out := out.set! 15 ((p[15]! <<< 1) ^^^ (if top == 1 then (135 : UInt8) else 0))
  return out

/-! ## The round function

Each AES4/AES10 call first whitens the input with the caller-supplied `j`,`i`,`l` blocks (which
vary by call site), then applies a *fixed* schedule of 4 or 10 rounds of
SubBytes→ShiftRows→MixColumns→AddRoundKey, keyed from the master extracted key's `1I`,`1J`,`1L`
(fixed for the whole `EState`, independent of the call site's `j`,`i`,`l`) — see
`round_vartime.go`'s `roundVartime.{AES4,AES10}`/`rounds`. -/

private def aesRound (s rk : Block) : Block := xor16 (mixColumns (shiftRows (subBytes s))) rk

private def roundsApply (s : Block) (schedule : List Block) : Block := schedule.foldl aesRound s

structure EState where
  I0 : Block
  I1 : Block
  J0 : Block
  J1 : Block
  J2 : Block
  L : Array Block -- L[0..7], L[0] = zero
  aes4Sched  : List Block -- [J0, I0, L1, zero], 4 entries
  aes10Sched : List Block -- [I0,J0,L1] repeated 3 times, then [I0], 10 entries

/-- `AES4(j, i, l; src)`: whiten with the call-site `j,i,l`, then 4 fixed-schedule rounds. -/
def aes4 (e : EState) (j i l src : Block) : Block := roundsApply (xor4 j i l src) e.aes4Sched

/-- `AES10(l; src)`: whiten with the call-site `l` alone, then 10 fixed-schedule rounds. -/
def aes10 (e : EState) (l src : Block) : Block := roundsApply (xor16 src l) e.aes10Sched

/-- `eState.init`, restricted to an already-48-byte extracted key (see module doc). -/
def initState (key48 : Block) : EState :=
  let i0 := key48.extract 0 16
  let j0 := key48.extract 16 32
  let l1 := key48.extract 32 48
  let i1 := doubleBlock i0
  let j1 := doubleBlock j0
  let j2 := doubleBlock j1
  let l0 := zero16
  let l2 := doubleBlock l1
  let l3 := xor16 l2 l1
  let l4 := doubleBlock l2
  let l5 := xor16 l4 l1
  let l6 := doubleBlock l3
  let l7 := xor16 l6 l1
  { I0 := i0, I1 := i1, J0 := j0, J1 := j1, J2 := j2
    L := #[l0, l1, l2, l3, l4, l5, l6, l7]
    aes4Sched := [j0, i0, l1, l0]
    aes10Sched := [i0, j0, l1, i0, j0, l1, i0, j0, l1, i0] }

/-! ## `aezHash`, restricted to no additional data

Still general over nonce length (the AD-hashing loop is what's dropped, not the nonce loop),
following `aez.go`'s `aezHash` with `ad = nil`, `tau = 0` (so the `tau`-derived leading block is
a hash of sixteen zero bytes). -/

private def oneZeroPad (src : Block) (sz : Nat) : Block :=
  Array.ofFn fun i : Fin 16 => if i.val < sz then src[i.val]! else if i.val == sz then 0x80 else 0

def aezHashNoAD (e : EState) (nonce : ByteArray) : Block := Id.run do
  -- Hash of tau (= 0 for Sphinx): buf is sixteen zero bytes; E(3,1).
  let j01 := xor16 e.J0 e.J1
  let mut sum := aes4 e j01 e.I1 (e.L[1]!) zero16
  -- Hash the nonce, one block at a time.
  let mut i : Nat := 1
  let mut ii := e.I1
  let mut off : Nat := 0
  let nLen := nonce.size
  while off + 16 ≤ nLen do
    let blk : Block := (nonce.extract off (off + 16)).data
    sum := xor16 sum (aes4 e e.J2 ii (e.L[i % 8]!) blk)
    off := off + 16
    if i % 8 == 0 then ii := doubleBlock ii
    i := i + 1
  -- Final fragment (or, per aez.go, the empty-nonce case too).
  if off < nLen || nLen == 0 then
    let frag : Block := oneZeroPad (nonce.extract off nLen).data (nLen - off)
    sum := xor16 sum (aes4 e e.J2 e.I0 (e.L[0]!) frag)
  return sum

/-! ## `aezTiny`: inputs shorter than 32 bytes -/

/-- `d = 0`: encipher; `d = 1`: decipher. -/
def aezTiny (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) : ByteArray := Id.run do
  let inBytes := inArr.size
  let (i0, rounds) :=
    if inBytes == 1 then (7, 24)
    else if inBytes == 2 then (7, 16)
    else if inBytes < 16 then (7, 10)
    else (6, 8)
  let half := (inBytes + 1) / 2
  let mut L : Block := zero16
  let mut R : Block := zero16
  for k in [0:half] do
    L := L.set! k (inArr.get! k)
  for k in [0:half] do
    R := R.set! k (inArr.get! (inBytes / 2 + k))
  let mut mask : UInt8 := 0x00
  let mut pad : UInt8 := 0x80
  if inBytes % 2 == 1 then
    let origR := R
    for k in [0:inBytes / 2] do
      R := R.set! k ((origR[k]! <<< 4) ||| (origR[k+1]! >>> 4))
    R := R.set! (inBytes / 2) (origR[inBytes / 2]! <<< 4)
    pad := 0x08
    mask := 0xf0
  let mut j : Int := 0
  let mut step : Int := 1
  if d ≠ 0 then
    if inBytes < 16 then
      let mut buf : Block := zero16
      for k in [0:inBytes] do buf := buf.set! k (inArr.get! k)
      buf := buf.set! 0 (buf[0]! ||| 0x80)
      buf := xor16 delta buf
      let tmp := aes4 e zero16 e.I1 (e.L[3]!) buf
      L := L.set! 0 (L[0]! ^^^ (tmp[0]! &&& 0x80))
    j := (rounds : Int) - 1
    step := -1
  for _ in [0:rounds / 2] do
    let mut buf1 : Block := zero16
    for k in [0:half] do buf1 := buf1.set! k (R[k]!)
    buf1 := buf1.set! (inBytes / 2) ((buf1[inBytes / 2]! &&& mask) ||| pad)
    buf1 := xor16 buf1 delta
    buf1 := buf1.set! 15 (buf1[15]! ^^^ UInt8.ofNat (j % 256).toNat)
    let tmp1 := aes4 e zero16 e.I1 (e.L[i0]!) buf1
    L := xor16 L tmp1

    let mut buf2 : Block := zero16
    for k in [0:half] do buf2 := buf2.set! k (L[k]!)
    buf2 := buf2.set! (inBytes / 2) ((buf2[inBytes / 2]! &&& mask) ||| pad)
    buf2 := xor16 buf2 delta
    buf2 := buf2.set! 15 (buf2[15]! ^^^ UInt8.ofNat (((j + step) % 256 + 256) % 256).toNat)
    let tmp2 := aes4 e zero16 e.I1 (e.L[i0]!) buf2
    R := xor16 R tmp2

    j := j + 2 * step

  -- Go's merge buffer is `[2*blockSize]byte` (32 bytes) here, not one block: `inBytes` can be
  -- up to 31, which overruns a 16-byte `Block`.
  let mut buf : Array UInt8 := Array.replicate inBytes 0
  for k in [0:inBytes / 2] do buf := buf.set! k (R[k]!)
  for k in [0:half] do buf := buf.set! (inBytes / 2 + k) (L[k]!)
  if inBytes % 2 == 1 then
    let orig := buf
    for k in [inBytes / 2 + 1 : inBytes] do
      -- Go: for k := inBytes-1; k > inBytes/2; k--  (descending; reads are independent per k
      -- from `orig` here, so direction does not matter for correctness).
      buf := buf.set! k ((orig[k]! >>> 4) ||| (orig[k-1]! <<< 4))
    buf := buf.set! (inBytes / 2) ((L[0]! >>> 4) ||| (R[inBytes / 2]! &&& 0xf0))
  let mut out : ByteArray := ⟨buf⟩
  if inBytes < 16 && d == 0 then
    let mut buf2 : Block := zero16
    for k in [0:inBytes] do buf2 := buf2.set! k (out.get! k)
    buf2 := buf2.set! 0 (buf2[0]! ||| 0x80)
    buf2 := xor16 delta buf2
    let tmp := aes4 e zero16 e.I1 (e.L[3]!) buf2
    out := out.set! 0 (out.get! 0 ^^^ (tmp[0]! &&& 0x80))
  return out

/-! ## `aezCore`: inputs of 32 bytes or more

`aezCorePass1`/`aezCorePass2` process the input in 32-byte chunks, all but the final chunk and
any `< 32`-byte fragment (`aezCorePass1Ref`/`aezCorePass2Ref`); the final chunk and fragment are
finished separately, matching `aezCore`. -/

private def chunk32 (b : ByteArray) (k : Nat) : Block := (b.extract (32*k) (32*k+16)).data
private def chunk32' (b : ByteArray) (k : Nat) : Block := (b.extract (32*k+16) (32*k+32)).data

/-- Pass 1: returns `(outPrefix, X)`. `nChunks = initialBytes / 32`. -/
private def pass1 (e : EState) (inArr : ByteArray) (nChunks : Nat) : ByteArray × Block := Id.run do
  let mut out : ByteArray := ByteArray.empty
  let mut x : Block := zero16
  let mut ii := e.I1
  for k in [0:nChunks] do
    let i := k + 1
    let inA := chunk32 inArr k
    let inB := chunk32' inArr k
    let tmp1 := aes4 e e.J0 ii (e.L[i % 8]!) inB
    let outA := xor16 inA tmp1
    let tmp2 := aes4 e zero16 e.I0 (e.L[0]!) outA
    let outB := xor16 inB tmp2
    x := xor16 x outB
    out := out ++ (⟨outA⟩ : ByteArray) ++ (⟨outB⟩ : ByteArray)
    if i % 8 == 0 then ii := doubleBlock ii
  return (out, x)

/-- Pass 2: returns `(outPrefix, Y)`, given `S` (fixed across all chunks) and pass 1's output
prefix to read `P1a`/`P1b` from. -/
private def pass2 (e : EState) (pass1Out : ByteArray) (s : Block) (nChunks : Nat) :
    ByteArray × Block := Id.run do
  let mut out : ByteArray := ByteArray.empty
  let mut y : Block := zero16
  let mut ii := e.I1
  for k in [0:nChunks] do
    let i := k + 1
    let p1a := chunk32 pass1Out k
    let p1b := chunk32' pass1Out k
    let tmp1 := aes4 e e.J1 ii (e.L[i % 8]!) s
    let a1 := xor16 p1a tmp1
    let b1 := xor16 p1b tmp1
    y := xor16 y a1
    let tmp2 := aes4 e zero16 e.I0 (e.L[0]!) b1
    let a2 := xor16 a1 tmp2
    let tmp3 := aes4 e e.J0 ii (e.L[i % 8]!) a2
    let b2 := xor16 b1 tmp3
    -- swap: final chunk is (b2, a2)
    out := out ++ (⟨b2⟩ : ByteArray) ++ (⟨a2⟩ : ByteArray)
    if i % 8 == 0 then ii := doubleBlock ii
  return (out, y)

def aezCore (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) : ByteArray := Id.run do
  let len := inArr.size
  let fragBytes := len % 32
  let initialBytes := len - fragBytes - 32
  let nChunks := initialBytes / 32

  -- Pass 1 (only when there is a >=64-byte prefix to process).
  let (pass1Out, x0) := if len ≥ 64 then pass1 e inArr nChunks else (ByteArray.empty, zero16)

  -- Finish X with the fragment.
  let frag := inArr.extract initialBytes (initialBytes + fragBytes)
  let mut x := x0
  if fragBytes ≥ 16 then
    let tmp1 := aes4 e zero16 e.I1 (e.L[4]!) (frag.extract 0 16).data
    x := xor16 x tmp1
    let tmp2 := aes4 e zero16 e.I1 (e.L[5]!) (oneZeroPad (frag.extract 16 fragBytes).data (fragBytes - 16))
    x := xor16 x tmp2
  else if fragBytes > 0 then
    let tmp := aes4 e zero16 e.I1 (e.L[4]!) (oneZeroPad frag.data fragBytes)
    x := xor16 x tmp

  -- Calculate S from the last 32 bytes.
  let lastA : Block := (inArr.extract (len - 32) (len - 16)).data
  let lastB : Block := (inArr.extract (len - 16) len).data
  let l1d := e.L[(1 + d) % 8]!
  let tmpS1 := aes4 e zero16 e.I1 l1d lastB
  let a : Block := xor4 x lastA delta tmpS1
  let tmpS2 := aes10 e l1d a
  let b : Block := xor16 lastB tmpS2
  let s : Block := xor16 a b

  -- Pass 2.
  let (pass2Out, y0) := if len ≥ 64 then pass2 e pass1Out s nChunks else (ByteArray.empty, zero16)

  -- Finish Y and finish encrypting the fragment.
  let mut y := y0
  let mut fragOut : ByteArray := ByteArray.empty
  if fragBytes ≥ 16 then
    let tmpA := aes10 e (e.L[4]!) s
    let outA : Block := xor16 (frag.extract 0 16).data tmpA
    let tmpYa := aes4 e zero16 e.I1 (e.L[4]!) outA
    y := xor16 y tmpYa
    let restLen := fragBytes - 16
    let tmpB := aes10 e (e.L[5]!) s
    let restOut : Array UInt8 :=
      Array.ofFn fun k : Fin restLen => (frag.extract 16 fragBytes).data[k.val]! ^^^ tmpB[k.val]!
    let tmpYb := aes4 e zero16 e.I1 (e.L[5]!) (oneZeroPad restOut restLen)
    y := xor16 y tmpYb
    fragOut := (⟨outA⟩ : ByteArray) ++ (⟨restOut⟩ : ByteArray)
  else if fragBytes > 0 then
    let tmpA := aes10 e (e.L[4]!) s
    let restOut : Array UInt8 :=
      Array.ofFn fun k : Fin fragBytes => frag.data[k.val]! ^^^ tmpA[k.val]!
    let tmpYa := aes4 e zero16 e.I1 (e.L[4]!) (oneZeroPad restOut fragBytes)
    y := xor16 y tmpYa
    fragOut := ⟨restOut⟩

  -- Finish the last two blocks.
  let l2d := e.L[(2 - d) % 8]!
  let tmpF1 := aes10 e l2d b
  let block0 : Block := xor16 a tmpF1
  let tmpF2 := aes4 e zero16 e.I1 l2d block0
  let block1 : Block := xor4 tmpF2 b delta y
  let lastTwo : ByteArray := (⟨block1⟩ : ByteArray) ++ (⟨block0⟩ : ByteArray)

  return pass2Out ++ fragOut ++ lastTwo

/-! ## Top-level dispatch, matching `encipher`/`decipher`/`SPRPEncrypt`/`SPRPDecrypt` -/

def encipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 0
  else aezCore e delta inArr 0

def decipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 1
  else aezCore e delta inArr 1

/-- **`crypto.SPRPEncrypt`**: `key` 48 bytes, `iv` 16 bytes, `tau = 0`, no additional data. -/
def sprpEncrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  encipher e delta msg

/-- **`crypto.SPRPDecrypt`**. With `tau = 0` the AEZ-native tag check always passes (there is no
tag), matching the Go wrapper's `panic`-on-`!ok` never firing in this configuration. -/
def sprpDecrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  decipher e delta msg

/-! ## Length preservation

AEZ in `τ = 0` mode is, by definition, a length-preserving strong pseudorandom permutation:
`encipher`/`decipher` never expand or truncate. Every branch of `aezTiny` and `aezCore` only
ever assembles its output from pieces whose sizes are determined by `inArr.size` itself
(`Array.replicate`/`.set!` preserve length; `aezCore`'s three regions total exactly
`initialBytes + fragBytes + 32 = inArr.size`) — so this is true by construction, and the 12
`sprp_aez.json` vectors confirm it empirically (`ciphertext_hex` is always exactly as long as
`plaintext_hex`, both directions). It is stated as an axiom rather than proved from
`aezCore`/`aezTiny`'s definitions, in the same spirit as `NIKE.X25519`'s
`curve25519_commutes`/`derivePub_safe`: pushing an imperative `for`-loop's size invariant
through Lean's `Id.run do` elaboration is mechanical but long, and out of scope for this pass
(see `Sphinx.Sphinx`, which is what actually needs this fact — it uses it to give `unwrap` a
packet-size-preserving *type*, not just a runtime-true property). -/

axiom sprpEncrypt_size (key : Array UInt8) (iv msg : ByteArray) :
    (sprpEncrypt key iv msg).size = msg.size

axiom sprpDecrypt_size (key : Array UInt8) (iv msg : ByteArray) :
    (sprpDecrypt key iv msg).size = msg.size

end CryptWalker.Sphinx.Crypto.AEZ
