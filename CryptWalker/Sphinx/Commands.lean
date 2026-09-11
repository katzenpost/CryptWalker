/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Commands

open CryptWalker.Sphinx.Constants
open CryptWalker.Util.Bytes (ofVector)

/-! # Sphinx per-hop routing commands

Port of `katzenpost/core/sphinx/commands/commands.go`. Every per-hop routing-info block is a
sequence of these, tag-prefixed and read until a `null` tag (or the block runs out) — see
`parseAll`.

Every command's wire size here is a *constant* (`nextNodeHopLength`, `1+recipientIDLength`,
`1+surbIDLength`, `1+4`), independent of the chosen NIKE/KEM or hop count — `Geometry.lean`
combines these with the per-scheme header/ciphertext size, but `Commands` itself needs no
`Geometry` parameter, unlike the Go `FromBytes(b, g)` (whose `g` argument is only there to reach
those same constants via `g.NextNodeHopLength` etc., which is itself constant-derived). -/

/-- `RoutingCommand`. `null` is the terminal marker (id `0x00`, no body) — Go represents it as
`cmd == nil`; a sum type is the more natural way to say the same thing here. -/
inductive RoutingCommand where
  | nextNodeHop (id : Vector UInt8 32) (mac : Vector UInt8 32)
  | recipient (id : Vector UInt8 32)
  | surbReply (id : Vector UInt8 16)
  | nodeDelay (delay : UInt32)
  | null
  deriving BEq, Repr

private def u32be (n : UInt32) : Vector UInt8 4 :=
  Vector.ofFn fun i : Fin 4 => (n >>> (8 * UInt32.ofNat (3 - i.val))).toUInt8

private def u32ofBE (b0 b1 b2 b3 : UInt8) : UInt32 :=
  (b0.toUInt32 <<< 24) ||| (b1.toUInt32 <<< 16) ||| (b2.toUInt32 <<< 8) ||| b3.toUInt32

/-- `RoutingCommand.ToBytes`. -/
def RoutingCommand.toBytes : RoutingCommand → ByteArray
  | .nextNodeHop id mac => ⟨#[0x01]⟩ ++ ofVector id ++ ofVector mac
  | .recipient id       => ⟨#[0x02]⟩ ++ ofVector id
  | .surbReply id       => ⟨#[0x03]⟩ ++ ofVector id
  | .nodeDelay d        => ⟨#[0x80]⟩ ++ ofVector (u32be d)
  | .null               => ⟨#[0x00]⟩

/-- `commands.FromBytes` for one command. `none` on success with no command (an empty buffer,
or the `null` terminal), matching Go's `cmd == nil`; `.error` on a malformed buffer. Returns the
parsed command (if any) together with the unconsumed remainder. -/
def fromBytesOne (b : ByteArray) : Except String (Option RoutingCommand × ByteArray) := do
  if b.size == 0 then
    pure (none, b)
  else if b.size == 1 then
    if b.get! 0 == 0x00 then pure (none, ByteArray.empty)
    else throw "sphinx: invalid per-hop command"
  else
    let id := b.get! 0
    let rest0 := b.extract 1 b.size
    match id with
    | 0x00 =>
      -- Terminal: any trailing bytes must be the zero padding of a fixed-size block.
      if rest0.data.all (· == 0) then pure (none, ByteArray.empty)
      else throw "sphinx: invalid per-hop command"
    | 0x01 =>
      if rest0.size < nextNodeHopLength - 1 then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! i.val
        let macV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! (32 + i.val)
        pure (some (.nextNodeHop idV macV), rest0.extract (nextNodeHopLength - 1) rest0.size)
    | 0x02 =>
      if rest0.size < recipientIDLength then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => rest0.get! i.val
        pure (some (.recipient idV), rest0.extract recipientIDLength rest0.size)
    | 0x03 =>
      if rest0.size < surbIDLength then throw "sphinx: invalid per-hop command"
      else
        let idV : Vector UInt8 16 := Vector.ofFn fun i : Fin 16 => rest0.get! i.val
        pure (some (.surbReply idV), rest0.extract surbIDLength rest0.size)
    | 0x80 =>
      if rest0.size < 4 then throw "sphinx: invalid per-hop command"
      else
        let d := u32ofBE (rest0.get! 0) (rest0.get! 1) (rest0.get! 2) (rest0.get! 3)
        pure (some (.nodeDelay d), rest0.extract 4 rest0.size)
    | _ => throw "sphinx: invalid per-hop command"

/-- Parse every command in a per-hop routing-info block, stopping at the terminal `null` (or an
exhausted buffer). This is what `NIKESphinx`/`KEMSphinx`'s unwrap runs over a decrypted per-hop
block. -/
partial def parseAll (b : ByteArray) : Except String (List RoutingCommand) := do
  match ← fromBytesOne b with
  | (none, _)        => pure []
  | (some cmd, rest) => pure (cmd :: (← parseAll rest))

end CryptWalker.Sphinx.Commands
