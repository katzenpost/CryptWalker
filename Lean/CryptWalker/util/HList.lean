
namespace CryptWalker.util.HList

universe u

def HList (τs : List (Type u)) : Type u := τs.foldr Prod PUnit

@[match_pattern] def HList.nil : HList [] := PUnit.unit

@[match_pattern] def HList.cons {τ : Type u} {τs : List (Type u)} (x : τ) (xs : HList τs) :
    HList (τ :: τs) := (x, xs)

def HList.rec {motive : (τs : List (Type u)) → HList τs → Sort u}
    (nil : motive [] HList.nil)
    (cons : {τ : Type u} → {τs : List (Type u)} → (x : τ) → (xs : HList τs) →
              motive τs xs → motive (τ :: τs) (HList.cons x xs))
    {τs : List (Type u)} (xs : HList τs) : motive τs xs :=
  match τs, xs with
  | [], PUnit.unit => nil
  | _ :: _, (x, xs) => cons x xs (HList.rec nil cons xs)

end CryptWalker.util.HList
