namespace CryptWalker.Util.newnat

def natToBytesAux (n : Nat) (acc : List UInt8) : List UInt8 :=
  if n == 0 then acc else natToBytesAux (n / 256) (UInt8.ofNat (n % 256) :: acc)
termination_by n
decreasing_by
  simp_wf
  simp_all
  omega

def natToBytes (n : Nat) : ByteArray :=
  ⟨(natToBytesAux n []).toArray⟩

theorem natToBytesAux_length_le : ∀ (k n : Nat) (acc : List UInt8),
    n < 256 ^ k → (natToBytesAux n acc).length ≤ acc.length + k := by
  intro k
  induction k with
  | zero =>
    intro n acc h
    have hn : n = 0 := by simpa using h
    subst hn
    rw [natToBytesAux]
    simp
  | succ k ih =>
    intro n acc h
    rw [natToBytesAux]
    split
    · simp
    · rw [Nat.pow_succ] at h
      have hc : (UInt8.ofNat (n % 256) :: acc).length = acc.length + 1 := rfl
      exact Nat.le_trans (ih (n / 256) (UInt8.ofNat (n % 256) :: acc) ((Nat.div_lt_iff_lt_mul (by decide)).mpr h)) (by omega)

theorem natToBytes_length_le_32 (n : Nat) (h : n < 256 ^ 32) :
    (natToBytes n).data.toList.length ≤ 32 := by
  simpa [natToBytes] using natToBytesAux_length_le 32 n [] h


end CryptWalker.Util.newnat
