/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Sphinx.Crypto.ChaCha20

/-! # ChaCha20 (original/Bernstein construction, 64-bit nonce)

Needed for one thing only: `hpqc/rand.NewDeterministicRandReader` — which
`internal/crypto.KDF` feeds `PacketKeys.blindingFactorSeed` into, whose first 32 bytes
`nike/x25519.scheme.GeneratePrivateKey` then reads directly as the next hop's blinding-factor
NIKE private key (`NewKeypair` performs no clamping at generation time; `X25519.curve25519`
clamps at use). `NIKESphinx`'s multi-hop blinding chain needs this to match Go byte-for-byte,
so it needs this cipher.

`github.com/katzenpost/chacha20`'s `NewDeterministicRandReader` always calls `chacha20.New(key,
nonce)` with an 8-byte **zero** nonce (`var nonce [8]byte`) — the original Bernstein variant
(not RFC 8439's 12-byte-nonce/32-bit-counter IETF variant), which places the nonce in state
words 14–15 and a 64-bit counter in words 12–13, both starting at zero. Since
`GeneratePrivateKey` only ever reads the first 32 bytes (half a block), only a *single* block
(counter = 0) is needed — no counter increment logic is implemented here.

Standard ChaCha20: the "expand 32-byte k" constants, 20 rounds (ten applications of the column
+ diagonal quarter-rounds), add the original state back in, serialize little-endian. -/

private def rotl (x : UInt32) (n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

private def sigma0 : UInt32 := 0x61707865
private def sigma1 : UInt32 := 0x3320646e
private def sigma2 : UInt32 := 0x79622d32
private def sigma3 : UInt32 := 0x6b206574

/-- 4 little-endian bytes as a word. -/
private def leWord (b0 b1 b2 b3 : UInt8) : UInt32 :=
  b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

/-- A word as 4 little-endian bytes. -/
private def leBytes (w : UInt32) : Array UInt8 :=
  #[w.toUInt8, (w >>> 8).toUInt8, (w >>> 16).toUInt8, (w >>> 24).toUInt8]

private def quarterRound (s : Array UInt32) (a b c d : Nat) : Array UInt32 := Id.run do
  let mut s := s
  s := s.set! a (s[a]! + s[b]!); s := s.set! d (rotl (s[d]! ^^^ s[a]!) 16)
  s := s.set! c (s[c]! + s[d]!); s := s.set! b (rotl (s[b]! ^^^ s[c]!) 12)
  s := s.set! a (s[a]! + s[b]!); s := s.set! d (rotl (s[d]! ^^^ s[a]!) 8)
  s := s.set! c (s[c]! + s[d]!); s := s.set! b (rotl (s[b]! ^^^ s[c]!) 7)
  return s

/-- One 64-byte ChaCha20 block: 32-byte key, 8-byte nonce, 64-bit counter (as two 32-bit
little-endian words). -/
def block (key : Array UInt8) (nonce : Array UInt8) (counterLo counterHi : UInt32) :
    Array UInt8 := Id.run do
  let keyWords : Array UInt32 := Array.ofFn fun i : Fin 8 =>
    leWord key[4*i.val]! key[4*i.val+1]! key[4*i.val+2]! key[4*i.val+3]!
  let nonceWords : Array UInt32 := Array.ofFn fun i : Fin 2 =>
    leWord nonce[4*i.val]! nonce[4*i.val+1]! nonce[4*i.val+2]! nonce[4*i.val+3]!
  let init : Array UInt32 :=
    #[sigma0, sigma1, sigma2, sigma3] ++ keyWords ++ #[counterLo, counterHi] ++ nonceWords
  let mut s := init
  for _ in [0:10] do
    -- Column rounds.
    s := quarterRound s 0 4 8 12
    s := quarterRound s 1 5 9 13
    s := quarterRound s 2 6 10 14
    s := quarterRound s 3 7 11 15
    -- Diagonal rounds.
    s := quarterRound s 0 5 10 15
    s := quarterRound s 1 6 11 12
    s := quarterRound s 2 7 8 13
    s := quarterRound s 3 4 9 14
  let out : Array UInt32 := Array.ofFn fun i : Fin 16 => s[i.val]! + init[i.val]!
  return (Array.range 16).foldl (fun acc i => acc ++ leBytes out[i]!) #[]

/-- The first `len ≤ 32` bytes of the ChaCha20 keystream for `key` under the all-zero 8-byte
nonce and counter zero — exactly `DeterministicRandReader(seed).Read(buf[:len])`'s first block,
which is all `GeneratePrivateKey` ever draws from it. -/
def keystream32 (key : Array UInt8) : Array UInt8 :=
  (block key (Array.replicate 8 0) 0 0).extract 0 32

end CryptWalker.Sphinx.Crypto.ChaCha20
