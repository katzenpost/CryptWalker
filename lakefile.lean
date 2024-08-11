import Lake
import Lake.Build.Job
open Lake DSL


set_option diagnostics true

require mathlib from git "https://github.com/leanprover-community/mathlib4"@"master"
require batteries from git "https://github.com/leanprover-community/batteries" @ "main"
require LeanSha from git "https://github.com/Ferinko/LeanSha" @ "master"
require LSpec from git "https://github.com/argumentcomputer/LSpec"@"main"

package «crypt_walker» where
  srcDir := "Lean"

@[default_target]
lean_lib «CryptWalker» where

@[test_driver]
lean_exe tests {
  root := `Tests.Main
}

target importTarget pkg : FilePath := do
  let oFile := pkg.buildDir / "c" / "curve25519-donna.o"
  let srcJob ← Lake.inputTextFile <| pkg.dir / "C" / "curve25519-donna.c"
  buildFileAfterDep oFile srcJob fun srcFile => do
    let flags := #["-I", toString (← getLeanIncludeDir), "-fPIC"]
    compileO oFile srcFile flags

extern_lib ffi pkg := do
  let job ← fetch <| pkg.target ``importTarget
  let libFile := pkg.nativeLibDir / nameToStaticLib "curve25519-donna"
  buildStaticLib libFile #[job]

extern_lib crypt_walker_for_lean pkg := do
  proc { cmd := "cargo", args := #["rustc", "--release", "--", "-C", "relocation-model=pic"], cwd := pkg.dir / "Rust" }
  let name := nameToStaticLib "crypt_walker_for_lean"
  let srcPath := pkg.dir / "Rust" / "target" / "release" / name
  IO.FS.createDirAll pkg.nativeLibDir
  let tgtPath := pkg.nativeLibDir / name
  IO.FS.writeBinFile tgtPath (← IO.FS.readBinFile srcPath)
  return pure tgtPath
