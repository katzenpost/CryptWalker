import Init.Data.UInt
import Init.Data.ByteArray
import Init.System.IO
import Init.Data.String

import CryptWalker.Util.newhex
import CryptWalker.Util.newnat
open CryptWalker.Util.newhex
open CryptWalker.Util.newnat

namespace CryptWalker.StreamCipher.Chacha20

def toUInt32 (s : String) : UInt32 :=
  let ba : ByteArray := falliableHexStringToByteArray s
  let n : UInt32 := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toUInt32) 0
  n

def word32ToBytes (n : UInt32) : ByteArray :=
  let bytes := ByteArray.mk $ Array.mk $ (ByteArray.toList $ natToBytes $ UInt32.toNat n).reverse
  bytes ++ ByteArray.mk (Array.mk (List.replicate (4 - bytes.size) 0))


def printHex (x : UInt32) : IO Unit :=
  IO.println s!"{x}"

def flipWord (x : UInt32) : UInt32 :=
  let a := (x &&& 0xFF) <<< 24
  let b := (x &&& 0xFF00) <<< 8
  let c := (x &&& 0xFF0000) >>> 8
  let d := (x &&& 0xFF000000) >>> 24
  a ||| b ||| c ||| d

def rotateLeft (x : UInt32) (n : UInt32) : UInt32 :=
  let shift := n % 32
  (x <<< shift) ||| (x >>> (32 - shift))

def quarterRound1 (a b c d : UInt32) : (UInt32 × UInt32 × UInt32 × UInt32) :=
  let aprime := a + b
  let dprime := d ^^^ aprime
  let dout := rotateLeft dprime 16
  (aprime, b, c, dout)

def quarterRound2 (a b c d : UInt32) : (UInt32 × UInt32 × UInt32 × UInt32) :=
  let cprime := c + d
  let bprime := b ^^^ cprime
  let bout := rotateLeft bprime 12
  (a, bout, cprime, d)

def quarterRound3 (a b c d : UInt32) : (UInt32 × UInt32 × UInt32 × UInt32) :=
  let aprime := a + b
  let dprime := d ^^^ aprime
  let dout := rotateLeft dprime 8
  (aprime, b, c, dout)

def quarterRound4 (a b c d : UInt32) : (UInt32 × UInt32 × UInt32 × UInt32) :=
  let cprime := c + d
  let bprime := b ^^^ cprime
  let bout := rotateLeft bprime 7
  (a, bout, cprime, d)

def fullQuarterRound (a b c d : UInt32) : (UInt32 × UInt32 × UInt32 × UInt32) :=
  let (a', b', c', d') := quarterRound1 a b c d
  let (a'', b'', c'', d'') := quarterRound2 a' b' c' d'
  let (a''', b''', c''', d''') := quarterRound3 a'' b'' c'' d''
  quarterRound4 a''' b''' c''' d'''

def displayState (state : List UInt32) : IO Unit :=
  state.forM printHex

def flipState (state : List UInt32) : List UInt32 :=
  state.map flipWord

def replaceNthElement {α : Type} (n : Nat) (v : α) (xs : List α) : List α :=
  match xs with
  | [] => []
  | (x :: xs) =>
    if n = 0 then v :: xs else x :: replaceNthElement (n - 1) v xs

def quarterRound (state : List UInt32) (w x y z : Nat) : List UInt32 :=
  let (w', x', y', z') := fullQuarterRound (state.get! w) (state.get! x) (state.get! y) (state.get! z)
  replaceNthElement w w' (replaceNthElement x x' (replaceNthElement y y' (replaceNthElement z z' state)))

def chaCha20BlockRound (state : List UInt32) : List UInt32 :=
  let state1 := quarterRound state  0 4  8 12
  let state2 := quarterRound state1 1 5  9 13
  let state3 := quarterRound state2 2 6 10 14
  let state4 := quarterRound state3 3 7 11 15
  let state5 := quarterRound state4 0 5 10 15
  let state6 := quarterRound state5 1 6 11 12
  let state7 := quarterRound state6 2 7  8 13
  let state8 := quarterRound state7 3 4  9 14
  state8

def chaCha20BlockLoop (state : List UInt32) (n : Nat) : List UInt32 :=
  if n = 0 then state
  else chaCha20BlockLoop (chaCha20BlockRound state) (n - 1)
  termination_by n

def chaCha20Block (key : List UInt32) (nonce : List UInt32) (count : UInt32) : List UInt32 :=
  if key.length ≠ 8
    then panic! "Invalid key length -- must be 256 bits"
  else
    if nonce.length ≠ 3
      then panic! "Invalid nonce length -- must be 96 bits"
    else
      let state := [toUInt32 "61707865", toUInt32 "3320646e", toUInt32 "79622d32", toUInt32 "6b206574",
                    flipWord (key.get! 0), flipWord (key.get! 1), flipWord (key.get! 2), flipWord (key.get! 3),
                    flipWord (key.get! 4), flipWord (key.get! 5), flipWord (key.get! 6), flipWord (key.get! 7),
                    count, flipWord (nonce.get! 0), flipWord (nonce.get! 1), flipWord (nonce.get! 2)]
      let mixedState := chaCha20BlockLoop state 10
      flipState (List.zipWith (· + ·) state mixedState)

def chaCha20Encrypt (key : List UInt32) (counter : UInt32) (nonce : List UInt32) (block : List UInt8) : List UInt8 :=
  if block.isEmpty then []
  else
    let keyStream := chaCha20Block key nonce counter
    let pad := keyStream.foldl (fun acc x => acc ++ word32ToBytes x) ByteArray.empty
    let padList := pad.toList
    let len := min 64 block.length
    let maskedBlock := List.zipWith (· ^^^ ·) (padList.take len) (block.take len)
    maskedBlock ++ chaCha20Encrypt key (counter + 1) nonce (block.drop len)
  decreasing_by sorry



end CryptWalker.StreamCipher.Chacha20
