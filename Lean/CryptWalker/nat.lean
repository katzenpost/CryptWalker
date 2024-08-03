
import Mathlib.Data.ByteArray


def natToBytesAux (n : Nat) (acc : List UInt8) : List UInt8 :=
  if n == 0 then acc else natToBytesAux (n / 256) (UInt8.ofNat (n % 256) :: acc)
decreasing_by sorry

def natToBytes (n : Nat) : ByteArray :=
  List.toByteArray (natToBytesAux n [])
