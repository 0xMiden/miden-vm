fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has_sve2 = target_features.split(',').any(|feature| feature == "sve2");

    // Gated identically to the Rust dispatch in the Poseidon2 module
    // (cfg(all(aarch64, target_feature = "sve2"))), so the compiled object and
    // the `extern "C"` call site are always both present or both absent.
    if target_arch == "aarch64" && has_sve2 {
        compile_arch_arm64_sve2_poseidon2();
    }
}

/// SVE2 Poseidon2 W12 packed-permutation kernel (compiler-scheduled C intrinsics).
fn compile_arch_arm64_sve2_poseidon2() {
    const P2_SVE2_PATH: &str = "arch/arm64-sve/poseidon2";

    println!("cargo:rerun-if-changed={P2_SVE2_PATH}/poseidon2_w12.c");

    cc::Build::new()
        .file(format!("{P2_SVE2_PATH}/poseidon2_w12.c"))
        .flag("-march=armv8.2-a+sve2")
        .flag("-O3")
        .compile("poseidon2_sve2");
}
