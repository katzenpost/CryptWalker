/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only

Inspired by the Haskell FFI X25519:
https://github.com/haskell-crypto/cryptonite/blob/master/Crypto/PubKey/Curve25519.hs
-/

import Mathlib.Data.ByteArray

@[extern "curve25519"]
opaque curve25519 : ByteArray → ByteArray → ByteArray

def dh (privateKey : ByteArray) (publicKey : ByteArray) : ByteArray :=
  if privateKey.size ≠ 32 then
    panic! "Private key must be 32 bytes long."
  else if publicKey.size ≠ 32 then
    panic! "Public key must be 32 bytes long."
  else
    curve25519 privateKey publicKey

def toPublic (privateKey : ByteArray) : ByteArray :=
  dh privateKey basepoint
  where
  basepoint : ByteArray := String.toAsciiByteArray "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

def generatePrivateKey : IO ByteArray := do
  let mut arr := ByteArray.mkEmpty 32
  for _ in [0:32] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  return arr
