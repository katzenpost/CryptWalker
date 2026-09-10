/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Crypto.HMAC
import CryptWalker.Util.Bytes

/-! # Helpers shared by NIKE-Sphinx and KEM-Sphinx

`sphinx.go`/`kemsphinx.go` share these via `package sphinx` (`v0AD`, `xorBytes`,
`commandsToBytes` as a `*Sphinx` method, etc.); `NIKESphinx`/`KEMSphinx` share them via this
file instead, since Lean's `private` is file-scoped. -/

namespace CryptWalker.Sphinx.Common

open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Crypto.HMAC (hmacSha256)
open CryptWalker.Util.Bytes (ofVector)

def v0AD : ByteArray := ⟨#[0, 0]⟩

def toVec32 (a : ByteArray) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => a.get! i.val

def xorBytes (a b : ByteArray) : ByteArray := ⟨a.data.mapIdx fun i x => x ^^^ b.data.getD i 0⟩

@[simp] theorem size_xorBytes (a b : ByteArray) : (xorBytes a b).size = a.size := by
  show (a.data.mapIdx _).size = a.size
  simp

def mac (key : Vector UInt8 32) (msg : ByteArray) : Vector UInt8 32 := hmacSha256 (ofVector key) msg

def zeroPadTo (n : Nat) (b : ByteArray) : ByteArray :=
  if b.size ≥ n then b else b ++ ⟨Array.replicate (n - b.size) 0⟩

/-- Drops the "no bare `NextNodeHop`"/"leave spare room for one" caller-discipline checks from
the Go original; nothing here is called with attacker-controlled commands. -/
def commandsToBytes (geom : Geometry) (cmds : List RoutingCommand) : Except String ByteArray := do
  let b := cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
  if b.size > geom.perHopRoutingInfoLength then
    throw "sphinx: invalid commands, oversized serialized block"
  pure b

end CryptWalker.Sphinx.Common
