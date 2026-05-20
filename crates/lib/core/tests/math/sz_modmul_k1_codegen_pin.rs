//! Cross-crate parity pins for the SZ-Horner k1 verifier's Fiat-Shamir initial sponge state.
//!
//! The Rust handler (`derive_alpha` in `u256_modmul.rs`) and the MASM emitter
//! (`miden-sz-codegen`) both compute `Poseidon(modulus)` and use the capacity lanes as the
//! seed of the FS transcript. They must agree exactly; otherwise alpha would mismatch in
//! production. The MASM-side codegen-vs-checked-in artifact drift is covered by
//! `crates/sz-codegen/tests/structural.rs`; this file only covers the host/codegen agreement
//! on the seed itself.

use miden_core_lib::handlers::{
    secp256k1_constants::{SECP256K1_BASE_PRIME_U16, SECP256K1_SCALAR_PRIME_U16},
    u256_modmul::modulus_seeded_initial_state as core_lib_seeded_state,
};
use miden_sz_codegen::modulus_seeded_initial_state as codegen_seeded_state;

#[test]
fn k1_base_precomputed_initial_state_pin() {
    let core_lib = core_lib_seeded_state(&SECP256K1_BASE_PRIME_U16);
    let codegen = codegen_seeded_state(&SECP256K1_BASE_PRIME_U16);
    assert_eq!(
        core_lib, codegen,
        "core-lib `derive_alpha` and sz-codegen emit divergent initial sponge states for the \
         secp256k1 base prime; alpha would mismatch in production."
    );
}

#[test]
fn k1_scalar_precomputed_initial_state_pin() {
    let core_lib = core_lib_seeded_state(&SECP256K1_SCALAR_PRIME_U16);
    let codegen = codegen_seeded_state(&SECP256K1_SCALAR_PRIME_U16);
    assert_eq!(
        core_lib, codegen,
        "core-lib `derive_alpha` and sz-codegen emit divergent initial sponge states for the \
         secp256k1 scalar prime; alpha would mismatch in production."
    );
}
