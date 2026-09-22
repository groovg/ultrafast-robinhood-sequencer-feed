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

fn main() {
    // Only the `ufsecp` feature links anything native beyond what the crates bring.
    println!("cargo:rerun-if-env-changed=UFSECP_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CLANG_RT_DIR");
    if std::env::var_os("CARGO_FEATURE_UFSECP").is_none() {
        return;
    }
    // Static, not the DLL: a clang-cl build of the DLL does not compile (a thread_local
    // inside a dllexport function), and static spares putting a DLL on PATH.
    let dir = PathBuf::from(std::env::var("UFSECP_LIB_DIR").expect(
        "the ufsecp feature needs UFSECP_LIB_DIR: the CMake build directory of UltrafastSecp256k1",
    ));
    for lib in ["ufsecp_s", "fastsecp256k1"] {
        let path = find(&dir, &format!("{lib}.lib"))
            .or_else(|| find(&dir, &format!("lib{lib}.a")))
            .unwrap_or_else(|| panic!("no {lib} library under {}", dir.display()));
        println!(
            "cargo:rustc-link-search=native={}",
            path.parent().unwrap().display()
        );
        println!("cargo:rustc-link-lib=static={lib}");
    }
    // A clang-cl build calls compiler-rt builtins that MSVC's linker does not bring.
    if let Ok(rt) = std::env::var("CLANG_RT_DIR") {
        println!("cargo:rustc-link-search=native={rt}");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64");
    }
}
