use std::path::{Path, PathBuf};

fn find(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == name) {
            return Some(path);
        }
        if path.is_dir()
            && let Some(hit) = find(&path, name)
        {
            return Some(hit);
        }
    }
    None
}

/// Link the first of `files` found under `dir` as a static library.
fn link_static(dir: &Path, files: &[&str]) {
    let path = files
        .iter()
        .find_map(|f| find(dir, f))
        .unwrap_or_else(|| panic!("none of {files:?} under {}", dir.display()));
    let file = path.file_name().unwrap().to_str().unwrap();
    let name = file
        .strip_prefix("lib")
        .unwrap_or(file)
        .trim_end_matches(".lib")
        .trim_end_matches(".a");
    // Relink when the library is rebuilt in place.
    println!("cargo:rerun-if-changed={}", path.display());
    println!(
        "cargo:rustc-link-search=native={}",
        path.parent().unwrap().display()
    );
    println!("cargo:rustc-link-lib=static={name}");
}

/// clang-cl on PATH or where the LLVM installer puts it.
fn clang_cl() -> Option<PathBuf> {
    let on_path = std::process::Command::new("clang-cl")
        .arg("--version")
        .output();
    if on_path.is_ok_and(|o| o.status.success()) {
        return Some("clang-cl".into());
    }
    let default = PathBuf::from(r"C:\Program Files\LLVM\bin\clang-cl.exe");
    default.exists().then_some(default)
}

fn main() {
    println!("cargo:rerun-if-changed=csrc");
    let mut fixedkey = cc::Build::new();
    fixedkey
        .file("csrc/fixedkey.c")
        .include("csrc/secp256k1")
        .warnings(false);
    // MSVC has no 128-bit integer, which makes libsecp256k1's field code slower than the
    // Rust it replaces (12.6 vs 9.3 µs per verify, against 7.6 with clang-cl).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        if let Some(clang) = clang_cl() {
            fixedkey.compiler(clang);
        } else {
            println!("cargo:warning=clang-cl not found, FixedKey built with MSVC is slower");
        }
    }
    fixedkey.compile("rhfeed_fixedkey");

    println!("cargo:rerun-if-env-changed=UFSECP_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CLANG_RT_DIR");
    if std::env::var_os("CARGO_FEATURE_UFSECP").is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var("UFSECP_LIB_DIR").expect(
        "the ufsecp feature needs UFSECP_LIB_DIR set to UltrafastSecp256k1's CMake build directory \
         (scripts/build-ufsecp.sh makes one)",
    ));
    // Windows names the static library ufsecp_s.lib when the DLL is built alongside it.
    // A plain ufsecp.lib there would be the DLL's import library, so it isn't in the list.
    link_static(&dir, &["ufsecp_s.lib", "libufsecp.a"]);
    link_static(&dir, &["fastsecp256k1.lib", "libfastsecp256k1.a"]);
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        // C++ runtime, and libatomic for the std::atomic calls clang leaves to it.
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=atomic");
    }
    // A clang-cl build calls compiler-rt builtins that MSVC's linker doesn't pull in.
    if let Ok(rt) = std::env::var("CLANG_RT_DIR") {
        println!("cargo:rustc-link-search=native={rt}");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64");
    }
}
