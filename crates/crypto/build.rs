fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has_sve = target_features.split(',').any(|feature| feature == "sve");

    if target_arch == "aarch64" && has_sve {
        compile_arch_arm64_sve();
    }
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
