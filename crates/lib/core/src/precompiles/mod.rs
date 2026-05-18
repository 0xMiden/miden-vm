//! Core precompile apps that back the MASM wrappers in `asm/crypto/`.
//!
//! Each precompile is a self-contained [`App`] implementation in its own file, paired with the
//! MASM wrapper that emits its tags via the deferred-DAG `sys::register_*` / `sys::evaluate`
//! events. The composite [`PrecompileSchema`] returned by [`schema`] routes tags to the right
//! app by `app_id`.
//!
//! - [`keccak256`] — Keccak256 preimage / digest / eq.
//! - [`sha512`] — SHA-512 preimage / digest / eq.
//! - [`ecdsa_k256_keccak`] — ECDSA secp256k1 / Keccak256 prehash verify.
//! - [`eddsa_ed25519`] — Ed25519 / SHA-512 verify (with externally supplied `k_digest`).
//!
//! [`App`]: miden_core::deferred::App
//! [`PrecompileSchema`]: miden_core::deferred::PrecompileSchema

mod codec;

pub mod ecdsa_k256_keccak;
pub mod eddsa_ed25519;
pub mod keccak256;
pub mod sha512;

pub use codec::{BYTES_PER_CHUNK, n_chunks};
pub use ecdsa_k256_keccak::EcdsaK256KeccakPrecompile;
pub use eddsa_ed25519::EddsaEd25519Precompile;
pub use keccak256::Keccak256Precompile;
pub use sha512::Sha512Precompile;

use alloc::boxed::Box;

use miden_core::deferred::{App, PrecompileSchema};

/// Build the composite [`PrecompileSchema`] hosting all four core precompile apps. Callers wire
/// it into a [`FastProcessor`] via [`FastProcessor::with_schema`] when running programs that use
/// the precompile MASM wrappers.
///
/// [`FastProcessor`]: miden_processor::FastProcessor
/// [`FastProcessor::with_schema`]: miden_processor::FastProcessor::with_schema
pub fn schema() -> PrecompileSchema {
    PrecompileSchema::new([
        Box::new(Keccak256Precompile) as Box<dyn App>,
        Box::new(Sha512Precompile),
        Box::new(EcdsaK256KeccakPrecompile),
        Box::new(EddsaEd25519Precompile),
    ])
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::Felt;

    use super::*;

    /// Pin the felt values that the per-precompile MASM files hardcode as
    /// `const APP_ID = ...` etc. Any change to the underlying app_id derivation (NAME, VERSION,
    /// params, DISCS) or to discriminant ordering will fail this test, forcing a matching update
    /// to the four precompile MASM files (keccak256.masm, sha512.masm, ecdsa_k256_keccak.masm,
    /// eddsa_ed25519.masm) so MASM and Rust never diverge silently.
    ///
    /// Update procedure on intentional change: bump VERSION (or rename a discriminant), re-run
    /// this test, copy the printed values into the `expected_*` constants below AND into the
    /// `const APP_ID` / `const D_*` declarations in each precompile MASM file.
    #[test]
    fn masm_constants_pinned_to_rust_values() {
        // Re-derived via `app_id_from(NAME, 1, b"", DISCS)` for each app. Pinned here so any
        // drift surfaces at CI time. Discriminant indices are positional in DISCS.
        const EXPECTED_KECCAK256_APP_ID: u64 = 15_236_188_148_055_918_137;
        const EXPECTED_SHA512_APP_ID: u64 = 3_974_822_377_943_316_543;
        const EXPECTED_ECDSA_K256_KECCAK_APP_ID: u64 = 6_573_419_657_329_570_818;
        const EXPECTED_EDDSA_ED25519_APP_ID: u64 = 12_237_732_355_729_770_957;

        assert_eq!(
            Keccak256Precompile::app_id().as_canonical_u64(),
            EXPECTED_KECCAK256_APP_ID,
            "keccak256 APP_ID drift — update keccak256.masm to match (got {})",
            Keccak256Precompile::app_id().as_canonical_u64(),
        );
        assert_eq!(
            Sha512Precompile::app_id().as_canonical_u64(),
            EXPECTED_SHA512_APP_ID,
            "sha512 APP_ID drift — update sha512.masm to match (got {})",
            Sha512Precompile::app_id().as_canonical_u64(),
        );
        assert_eq!(
            EcdsaK256KeccakPrecompile::app_id().as_canonical_u64(),
            EXPECTED_ECDSA_K256_KECCAK_APP_ID,
            "ecdsa_k256_keccak APP_ID drift — update ecdsa_k256_keccak.masm to match (got {})",
            EcdsaK256KeccakPrecompile::app_id().as_canonical_u64(),
        );
        assert_eq!(
            EddsaEd25519Precompile::app_id().as_canonical_u64(),
            EXPECTED_EDDSA_ED25519_APP_ID,
            "eddsa_ed25519 APP_ID drift — update eddsa_ed25519.masm to match (got {})",
            EddsaEd25519Precompile::app_id().as_canonical_u64(),
        );

        // Per-app discriminant indices are positional in DISCS; pin them explicitly so a
        // reorder is caught.
        assert_eq!(Keccak256Precompile::D_PREIMAGE.as_canonical_u64(), 0);
        assert_eq!(Keccak256Precompile::D_DIGEST.as_canonical_u64(), 1);
        assert_eq!(Keccak256Precompile::D_EQ.as_canonical_u64(), 2);
        assert_eq!(Sha512Precompile::D_PREIMAGE.as_canonical_u64(), 0);
        assert_eq!(Sha512Precompile::D_DIGEST.as_canonical_u64(), 1);
        assert_eq!(Sha512Precompile::D_EQ.as_canonical_u64(), 2);
        assert_eq!(EcdsaK256KeccakPrecompile::D_VERIFY.as_canonical_u64(), 0);
        assert_eq!(EddsaEd25519Precompile::D_VERIFY.as_canonical_u64(), 0);
    }

    #[test]
    fn schema_composites_all_four_apps() {
        let s = schema();
        let ids: Vec<Felt> = s.app_ids();
        assert_eq!(ids.len(), 4);
        assert!(ids.contains(&Keccak256Precompile::app_id()));
        assert!(ids.contains(&Sha512Precompile::app_id()));
        assert!(ids.contains(&EcdsaK256KeccakPrecompile::app_id()));
        assert!(ids.contains(&EddsaEd25519Precompile::app_id()));
    }
}
