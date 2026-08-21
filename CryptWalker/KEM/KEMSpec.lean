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

@[extern "generate_key_pair"]
def generate : EncDecM (PublicKey × PrivateKey) := fun s =>
  let (⟨pk, sk, _⟩, s) := encDecSpec.generate s
  ((pk, sk), s)

@[extern "encapsulate"]
def encap : PublicKey → EncDecM (Ciphertext × Plaintext) := encDecSpec.encap

@[extern "decapsulate"]
def decap : PrivateKey → Ciphertext → EncDecM Plaintext := encDecSpec.decap

@[extern "is_plaintext_equal"]
instance : DecidableEq Plaintext := encDecSpec.plaintextEq

def IsEncapsulation (sk : PrivateKey) (c : Ciphertext) (k : Plaintext) :=
  ∀ s, (decap sk c s).1 = k

def KeyPair (pk : PublicKey) (sk : PrivateKey) :=
  ∀ s, let (c, k) := (encap pk s).1; IsEncapsulation sk c k

theorem SatisfiesM_StateM_eq {σ α} {p : α → Prop} {x : StateM σ α} :
    SatisfiesM p x ↔ ∀ s, p (x s).1 := by
  constructor
  · rintro ⟨x', rfl⟩ s
    exact (x' s).1.2
  · intro h
    exact ⟨fun s => (⟨(x s).1, h s⟩, (x s).2), rfl⟩

theorem generate_ok : SatisfiesM (fun (pk, sk) => KeyPair pk sk) generate :=
  SatisfiesM_StateM_eq.2 fun s => (encDecSpec.generate s).1.2.2

theorem encap_ok {pk sk} (h : KeyPair pk sk) :
    SatisfiesM (fun (c, k) => IsEncapsulation sk c k) (encap pk) :=
  SatisfiesM_StateM_eq.2 h

theorem decap_ok {sk ct k} (h : IsEncapsulation sk ct k) :
    SatisfiesM (fun k' => k' = k) (decap sk ct) :=
  SatisfiesM_StateM_eq.mpr h
