fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has_sve = target_features.split(',').any(|feature| feature == "sve");
    let has_sve2 = target_features.split(',').any(|feature| feature == "sve2");

    if target_arch == "aarch64" && has_sve {
        compile_arch_arm64_sve();
    }
    // Gated identically to the Rust dispatch in the Poseidon2 module
    // (cfg(all(aarch64, linux, target_feature = "sve2"))), so the compiled
    // object and the `extern "C"` call site are always both present or both absent.
    if target_arch == "aarch64" && target_os == "linux" && has_sve2 {
        compile_arch_arm64_sve2_poseidon2();
    }
}

/// SVE2 Poseidon2 W12 packed-permutation kernel (compiler-scheduled C
/// intrinsics, same pattern as the RPO SVE kernel above).
fn compile_arch_arm64_sve2_poseidon2() {
    const P2_SVE2_PATH: &str = "arch/arm64-sve/poseidon2";

    println!("cargo:rerun-if-changed={P2_SVE2_PATH}/poseidon2_w12.c");

    cc::Build::new()
        .file(format!("{P2_SVE2_PATH}/poseidon2_w12.c"))
        .flag("-march=armv8.2-a+sve2")
        .flag("-O3")
        .compile("poseidon2_sve2");
}

fn compile_arch_arm64_sve() {
    const RPO_SVE_PATH: &str = "arch/arm64-sve/rpo";

    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.c");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.h");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/rpo_hash_128bit.h");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/rpo_hash_256bit.h");

    cc::Build::new()
        .file(format!("{RPO_SVE_PATH}/library.c"))
        .flag("-march=armv8-a+sve")
        .flag("-O3")
        .compile("rpo_sve");
}
