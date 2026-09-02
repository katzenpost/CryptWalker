import Std.Tactic.Do

open Std.Do

namespace CryptWalker.KEM.KEM

inductive KEMError where
  | badCiphertext
  | unsafePublicKey
deriving DecidableEq


structure KEM where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext : Type
  [pubI  : Inhabited PublicKey]
  [privI : Inhabited PrivateKey]
  [ctI   : Inhabited Ciphertext]
  [ptI   : Inhabited Plaintext]
  /-- Inhabitance witness for `State`, nothing more. The state a scheme is
  actually run against carries its randomness and must be supplied by the
  caller; never execute against `stateI.default`. -/
  [stateI : Inhabited State]

  publicKeySize  : Nat
  privateKeySize : Nat
  ciphertextSize : Nat
  plaintextSize  : Nat

  encodePublicKey  : PublicKey  → Vector UInt8 publicKeySize
  decodePublicKey  : Vector UInt8 publicKeySize  → Option PublicKey
  encodePrivateKey : PrivateKey → Vector UInt8 privateKeySize
  decodePrivateKey : Vector UInt8 privateKeySize → Option PrivateKey
  encodeCiphertext : Ciphertext → Vector UInt8 ciphertextSize
  decodeCiphertext : Vector UInt8 ciphertextSize → Option Ciphertext
  encodePlaintext  : Plaintext  → Vector UInt8 plaintextSize

  decap : PrivateKey → Ciphertext → EStateM KEMError State Plaintext
  encap : PublicKey → EStateM KEMError State (Ciphertext × Plaintext)
  generate : EStateM KEMError State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s c k s', encap pk s = .ok (c, k) s' → ∀ t, ∃ t', decap sk c t = .ok k t'})

  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_ct   : ∀ c,  decodeCiphertext (encodeCiphertext c)  = some c

  [plaintextEq : DecidableEq Plaintext]


instance : Inhabited KEM := ⟨{
  State := Unit
  PublicKey := Unit
  PrivateKey := Unit
  Ciphertext := Unit
  Plaintext := Unit

  publicKeySize  := 0
  privateKeySize := 0
  ciphertextSize := 0
  plaintextSize  := 0

  encodePublicKey  := fun _ => #v[]
  decodePublicKey  := fun _ => some ()
  encodePrivateKey := fun _ => #v[]
  decodePrivateKey := fun _ => some ()
  encodeCiphertext := fun _ => #v[]
  decodeCiphertext := fun _ => some ()
  encodePlaintext  := fun _ => #v[]

  decap := fun _ _ => pure ()
  encap := fun _ => pure ((), ())
  generate := pure ⟨(), (), fun _ _ _ _ _ t => ⟨t, rfl⟩⟩

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_ct   := fun _ => rfl

  plaintextEq := inferInstance
}⟩

section Spec

variable (kemSpec : KEM)

instance : Inhabited kemSpec.State := kemSpec.stateI

abbrev KEMM := EStateM KEMError kemSpec.State

abbrev PublicKey : Type := kemSpec.PublicKey
instance : Inhabited (PublicKey kemSpec) := kemSpec.pubI

abbrev PrivateKey : Type := kemSpec.PrivateKey
instance : Inhabited (PrivateKey kemSpec) := kemSpec.privI

abbrev Ciphertext : Type := kemSpec.Ciphertext
instance : Inhabited (Ciphertext kemSpec) := kemSpec.ctI

abbrev Plaintext : Type := kemSpec.Plaintext
instance : Inhabited (Plaintext kemSpec) := kemSpec.ptI

instance : DecidableEq (Plaintext kemSpec) := kemSpec.plaintextEq

def generate : KEMM kemSpec (PublicKey kemSpec × PrivateKey kemSpec) := do
  let ⟨pk, sk, _⟩ ← kemSpec.generate
  pure (pk, sk)

def encap : PublicKey kemSpec → KEMM kemSpec (Ciphertext kemSpec × Plaintext kemSpec) :=
  kemSpec.encap

def decap : PrivateKey kemSpec → Ciphertext kemSpec → KEMM kemSpec (Plaintext kemSpec) :=
  kemSpec.decap

def IsEncapsulation (sk : PrivateKey kemSpec) (c : Ciphertext kemSpec) (k : Plaintext kemSpec) :=
  ∀ t, ∃ t', decap kemSpec sk c t = .ok k t'

def KeyPair (pk : PublicKey kemSpec) (sk : PrivateKey kemSpec) :=
  ∀ s c k s', encap kemSpec pk s = .ok (c, k) s' → IsEncapsulation kemSpec sk c k

/-- A triple for a computation that need not succeed: whenever it returns, the result
satisfies `p`. Failure is left unconstrained, because neither `generate` nor `encap` is total.
`CryptWalker.KEM.Adapter` throws `.unsafePublicKey` when a NIKE public key fails its safety
check, so no `KEM` can be assumed to always return. -/
theorem EStateM_triple_ok {ε σ α} {p : α → Prop} {x : EStateM ε σ α}
    (h : ∀ t a t', x t = .ok a t' → p a) :
    ⦃⌜True⌝⦄ x ⦃post⟨fun a => ⌜p a⌝, fun _ => ⌜True⌝⟩⦄ := by
  intro t _
  simp only [WP.wp, PredTrans.apply, EStateM.run]
  cases hx : x t with
  | ok a t'    => exact h t a t' hx
  | error e t' => trivial

/-- The stronger triple, for a computation that cannot fail. Only `decap` gets to use it, and
only under a hypothesis that already names a successful encapsulation. -/
theorem EStateM_triple {ε σ α} {p : α → Prop} {x : EStateM ε σ α}
    (h : ∀ t, ∃ a t', x t = .ok a t' ∧ p a) :
    ⦃⌜True⌝⦄ x ⦃post⟨fun a => ⌜p a⌝, fun _ => ⌜False⌝⟩⦄ := by
  intro t _
  obtain ⟨a, t', ht, hp⟩ := h t
  simp only [WP.wp, PredTrans.apply, EStateM.run, ht]
  exact hp

/-- Whatever `generate` returns is a valid key pair: the witness travels in its return type. -/
theorem generate_keyPair {t r t'} (hr : generate kemSpec t = .ok r t') :
    KeyPair kemSpec r.1 r.2 := by
  simp only [generate, bind, EStateM.bind] at hr
  split at hr
  · rename_i a _ _
    simp only [pure, EStateM.pure, EStateM.Result.ok.injEq] at hr
    obtain ⟨rfl, -⟩ := hr
    exact a.2.property
  · exact absurd hr (by simp)

@[spec] theorem generate_ok :
    ⦃⌜True⌝⦄ generate kemSpec
    ⦃post⟨fun (pk, sk) => ⌜KeyPair kemSpec pk sk⌝, fun _ => ⌜True⌝⟩⦄ :=
  EStateM_triple_ok fun _ _ _ hr => generate_keyPair kemSpec hr

@[spec] theorem encap_ok {pk sk} (h : KeyPair kemSpec pk sk) :
    ⦃⌜True⌝⦄ encap kemSpec pk
    ⦃post⟨fun (c, k) => ⌜IsEncapsulation kemSpec sk c k⌝, fun _ => ⌜True⌝⟩⦄ :=
  EStateM_triple_ok fun t r t' hr => h t r.1 r.2 t' hr

@[spec] theorem decap_ok {sk ct k} (h : IsEncapsulation kemSpec sk ct k) :
    ⦃⌜True⌝⦄ decap kemSpec sk ct ⦃post⟨fun k' => ⌜k' = k⌝, fun _ => ⌜False⌝⟩⦄ :=
  EStateM_triple fun t => let ⟨t', ht⟩ := h t; ⟨k, t', ht, rfl⟩

def roundTrip : KEMM kemSpec Bool := do
  let (pk, sk) ← generate kemSpec
  let (c, k)   ← encap kemSpec pk
  let k'       ← decap kemSpec sk c
  return k' == k

/-- Generate, encapsulate, decapsulate: the plaintext that comes back is the one that went in.
Any of the three steps may fail, so this constrains the successful runs only. -/
theorem roundTrip_ok :
    ⦃⌜True⌝⦄ roundTrip kemSpec ⦃post⟨fun b => ⌜b = true⌝, fun _ => ⌜True⌝⟩⦄ := by
  refine EStateM_triple_ok fun t b t' hr => ?_
  simp only [roundTrip, bind, EStateM.bind] at hr
  split at hr
  case _ r1 s1 hgen =>
    split at hr
    case _ r2 s2 henc =>
      split at hr
      case _ k' s3 hdec =>
        simp only [pure, EStateM.pure, EStateM.Result.ok.injEq] at hr
        obtain ⟨rfl, -⟩ := hr
        obtain ⟨s4, hd⟩ :=
          generate_keyPair kemSpec hgen s1 r2.1 r2.2 s2 (by simpa using henc) s2
        rw [hdec, EStateM.Result.ok.injEq] at hd
        simp [hd.1]
      case _ => exact absurd hr (by simp)
    case _ => exact absurd hr (by simp)
  case _ => exact absurd hr (by simp)

end Spec

end CryptWalker.KEM.KEM
