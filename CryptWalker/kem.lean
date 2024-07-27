import Batteries.Classes.SatisfiesM

structure EncDecSpec where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext : Type
  decap : PrivateKey → Ciphertext → StateM State Plaintext
  encap : PublicKey → StateM State (Ciphertext × Plaintext)
  init : State
  generate : StateM State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s, let (c, k) := (encap pk s).1; ∀ s, (decap sk c s).1 = k})
  [plaintextEq : DecidableEq Plaintext]

instance : Inhabited EncDecSpec := ⟨{
  State := Unit
  PublicKey := Unit
  PrivateKey := Unit
  Ciphertext := Unit
  Plaintext := Unit
  decap := fun _ _ => pure ()
  encap := fun _ => pure ((), ())
  init := ()
  generate := pure ⟨(), (), fun () () => rfl⟩
  plaintextEq := inferInstance
}⟩

opaque encDecSpec : EncDecSpec

instance : Inhabited encDecSpec.State := ⟨encDecSpec.init⟩

abbrev EncDecM := StateM encDecSpec.State

def PublicKey : Type := encDecSpec.PublicKey
instance : Inhabited PublicKey := ⟨(encDecSpec.generate default).1.1⟩

def PrivateKey : Type := encDecSpec.PrivateKey
instance : Inhabited PrivateKey := ⟨(encDecSpec.generate default).1.2.1⟩

def Ciphertext : Type := encDecSpec.Ciphertext
instance : Inhabited Ciphertext :=
  ⟨(encDecSpec.encap (encDecSpec.generate default).1.1 default).1.1⟩

def Plaintext : Type := encDecSpec.Plaintext
instance : Inhabited Plaintext :=
  ⟨(encDecSpec.encap (encDecSpec.generate default).1.1 default).1.2⟩

def generate : EncDecM (PublicKey × PrivateKey) := fun s =>
  let (⟨pk, sk, _⟩, s) := encDecSpec.generate s
  ((pk, sk), s)

def encap : PublicKey → EncDecM (Ciphertext × Plaintext) := encDecSpec.encap

def decap : PrivateKey → Ciphertext → EncDecM Plaintext := encDecSpec.decap

instance : DecidableEq Plaintext := encDecSpec.plaintextEq

def IsEncapsulation (sk : PrivateKey) (c : Ciphertext) (k : Plaintext) :=
  ∀ s, (decap sk c s).1 = k

def KeyPair (pk : PublicKey) (sk : PrivateKey) :=
  ∀ s, let (c, k) := (encap pk s).1; IsEncapsulation sk c k

theorem generate_ok : SatisfiesM (fun (pk, sk) => KeyPair pk sk) generate := by
  simp [generate]; intro s; split; rename_i h1 s1 _; exact h1

theorem encap_ok {pk sk} (h : KeyPair pk sk) :
    SatisfiesM (fun (c, k) => IsEncapsulation sk c k) (encap pk) := by simpa using h

theorem decap_ok {sk c k} (h : IsEncapsulation sk c k) :
    SatisfiesM (fun k' => k' = k) (decap sk c) := by simpa using h
