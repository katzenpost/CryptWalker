
def byteToHex (b : UInt8) : String :=
  let high := hexDigitRepr (b.toNat / 16)
  let low := hexDigitRepr (b.toNat % 16)
  s!"{high}{low}"

def byteArrayToHex (blob : ByteArray) : String :=
  blob.foldl (fun acc b => acc ++ byteToHex b) ""

instance : Repr ByteArray where
  reprPrec a _ := byteArrayToHex a

instance : ToString ByteArray where
  toString x :=
    byteArrayToHex x
