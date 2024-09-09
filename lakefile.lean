import Lake
open Lake DSL

package "CryptWalker" where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4"@"v4.11.0"

@[default_target]
lean_lib «CryptWalker» where
