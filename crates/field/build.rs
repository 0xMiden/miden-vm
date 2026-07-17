use std::env;

fn main() {
    println!("cargo::rerun-if-env-changed=MIDENC_TARGET_IS_MIDEN_VM");
    println!("cargo::rustc-check-cfg=cfg(miden)");

    // `cargo-miden` compiles Rust to Wasm which will then be compiled to Miden VM code by `midenc`.
    // When targeting a "real" Wasm runtime (e.g. `wasm32-unknown-unknown` for a web SDK), we want a
    // regular felt representation instead.
    //
    // Treat this as a boolean flag to avoid enabling the `miden` cfg when the variable is set but
    // empty (e.g. `MIDENC_TARGET_IS_MIDEN_VM=`).
    let target_is_miden_vm = env::var("MIDENC_TARGET_IS_MIDEN_VM").is_ok_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true")
    });

    if target_is_miden_vm {
        println!("cargo::rustc-cfg=miden");
    }
}
