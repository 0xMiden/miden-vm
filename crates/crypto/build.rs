fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has_std = std::env::var_os("CARGO_FEATURE_STD").is_some();
    let has_sve = target_features.split(',').any(|feature| feature == "sve");
    let has_sve2 = target_features.split(',').any(|feature| feature == "sve2");

    if target_arch == "aarch64" {
        compile_arch_arm64_eidos(has_std, has_sve, has_sve2);
    }
    if target_arch == "aarch64" && has_sve {
        compile_arch_arm64_sve();
    }
    // Gated identically to the Rust dispatch in the Poseidon2 module
    // (cfg(all(aarch64, target_feature = "sve2"))), so the compiled object and
    // the `extern "C"` call site are always both present or both absent.
    if target_arch == "aarch64" && has_sve2 {
        compile_arch_arm64_sve2_poseidon2();
    }
}

/// Builds the Eidos ARM dispatch libraries. `std` builds contain every tier because selection is
/// deferred to runtime; `no_std` only contains the AArch64 baseline and tiers selected at compile
/// time. Later Eidos kernel tasks add their source files under this directory, which this build
/// boundary picks up without changing the tier policy.
fn compile_arch_arm64_eidos(has_std: bool, has_sve: bool, has_sve2: bool) {
    const EIDOS_PATH: &str = "arch/arm64-eidos";

    println!("cargo:rerun-if-changed={EIDOS_PATH}");

    compile_arch_arm64_eidos_tier("eidos_neon", "eidos_neon.c", "armv8-a");
    if has_std || has_sve || has_sve2 {
        compile_arch_arm64_eidos_tier("eidos_sve", "eidos_sve.c", "armv8-a+sve");
    }
    if has_std || has_sve2 {
        compile_arch_arm64_eidos_tier("eidos_sve2", "eidos_sve2.c", "armv8.2-a+sve2");
    }
}

fn compile_arch_arm64_eidos_tier(library: &str, kernel: &str, march: &str) {
    const EIDOS_PATH: &str = "arch/arm64-eidos";
    let kernel_path = format!("{EIDOS_PATH}/{kernel}");
    let mut build = cc::Build::new();

    // The stubs validate the stable pointer ABI before a tier has an implementation. Once a
    // kernel source is present, it joins the same tier archive and inherits that tier's ISA flag.
    build.file(format!("{EIDOS_PATH}/dispatch_stubs.c"));
    if std::path::Path::new(&kernel_path).exists() {
        build.file(kernel_path);
    }
    build
        .flag("-std=c11")
        .flag(format!("-march={march}"))
        .flag("-O3")
        .compile(library);
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
