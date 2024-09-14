import Lake
open Lake DSL

package "CryptWalker" where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4"@"v4.11.0"

require Bench from git "https://github.com/david415/bench"

@[default_target]
lean_lib «CryptWalker» where

lean_exe CryptWalker.Data.test
lean_exe CryptWalker.NIKE.test
lean_exe CryptWalker.KEM.test
lean_exe CryptWalker.NIKE.benchmark
