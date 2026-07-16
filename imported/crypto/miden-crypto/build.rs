fn main() {
    #[cfg(target_feature = "sve")]
    compile_arch_arm64_sve();
}

#[cfg(target_feature = "sve")]
fn compile_arch_arm64_sve() {
    const RPO_SVE_PATH: &str = "arch/arm64-sve/rpo";

    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.c");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.h");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/rpo_hash.h");

    cc::Build::new()
        .file(format!("{RPO_SVE_PATH}/library.c"))
        .flag("-march=armv8-a+sve")
        .flag("-O3")
        .compile("rpo_sve");
}
