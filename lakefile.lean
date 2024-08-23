import Lake
import Lake.Build.Job
open Lake DSL


set_option diagnostics true

require mathlib from git "https://github.com/leanprover-community/mathlib4"@"master"
require batteries from git "https://github.com/leanprover-community/batteries" @ "main"
require LeanSha from git "https://github.com/Ferinko/LeanSha" @ "master"

package «crypt_walker» where
  srcDir := "Lean"

@[default_target]
lean_lib «CryptWalker» where

@[test_driver]
lean_exe tests {
  root := `Tests.Main
}
