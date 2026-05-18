//! Core precompile apps that back the MASM wrappers in `asm/crypto/`.
//!
//! Each precompile is a self-contained [`Precompile`] implementation in its own file, paired
//! with the MASM wrapper that emits its tags via the deferred-DAG `sys::register_*` /
//! `sys::evaluate` events. The composite [`PrecompileSchema`] returned by [`schema`] routes
//! tags to the right precompile by id.
//!
//! - [`keccak256`] — Keccak256 preimage / digest / eq.
//! - [`sha512`] — SHA-512 preimage / digest / eq.
//! - [`ecdsa_k256_keccak`] — ECDSA secp256k1 / Keccak256 prehash verify.
//! - [`eddsa_ed25519`] — Ed25519 / SHA-512 verify (with externally supplied `k_digest`).
//!
//! [`Precompile`]: miden_core::deferred::Precompile
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

use miden_core::deferred::{Precompile, PrecompileSchema};

/// Build the composite [`PrecompileSchema`] hosting all four core precompile apps. Callers wire
/// it into a [`FastProcessor`] via [`FastProcessor::with_schema`] when running programs that use
/// the precompile MASM wrappers.
///
/// [`FastProcessor`]: miden_processor::FastProcessor
/// [`FastProcessor::with_schema`]: miden_processor::FastProcessor::with_schema
pub fn schema() -> PrecompileSchema {
    PrecompileSchema::new([
        Box::new(Keccak256Precompile) as Box<dyn Precompile>,
        Box::new(Sha512Precompile),
        Box::new(EcdsaK256KeccakPrecompile),
        Box::new(EddsaEd25519Precompile),
    ])
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{Felt, deferred::precompile_id};

    use super::*;

    /// Pin the felt values that the per-precompile MASM files hardcode as
    /// `const APP_ID = ...` / `const *_TAG_ID = ...`. `app_id()` returns a hardcoded literal; this
    /// test asserts it equals both the MASM mirror (`EXPECTED_*`) and the live
    /// [`precompile_id`] derivation (NAME + VERSION), so MASM, the Rust literal, and the
    /// derivation never diverge silently. (`PrecompileSchema::new` also enforces the
    /// literal-vs-derivation half at composite-construction time.)
    ///
    /// Update procedure on intentional change: bump VERSION, run this test, copy each printed
    /// `got` value into the precompile's `app_id()` literal, the `EXPECTED_*` constant below,
    /// AND the `const APP_ID` line of the matching `.masm` file.
    #[test]
    fn masm_constants_pinned_to_rust_values() {
        const EXPECTED_KECCAK256_APP_ID: u64 = 12_495_655_595_326_449_568;
        const EXPECTED_SHA512_APP_ID: u64 = 5_915_489_169_965_270_201;
        const EXPECTED_ECDSA_K256_KECCAK_APP_ID: u64 = 11_898_598_695_480_032_786;
        const EXPECTED_EDDSA_ED25519_APP_ID: u64 = 17_524_510_362_207_076_881;

        for (name, app_id, expected, derived) in [
            (
                "keccak256",
                Keccak256Precompile::app_id(),
                EXPECTED_KECCAK256_APP_ID,
                precompile_id(&Keccak256Precompile),
            ),
            (
                "sha512",
                Sha512Precompile::app_id(),
                EXPECTED_SHA512_APP_ID,
                precompile_id(&Sha512Precompile),
            ),
            (
                "ecdsa_k256_keccak",
                EcdsaK256KeccakPrecompile::app_id(),
                EXPECTED_ECDSA_K256_KECCAK_APP_ID,
                precompile_id(&EcdsaK256KeccakPrecompile),
            ),
            (
                "eddsa_ed25519",
                EddsaEd25519Precompile::app_id(),
                EXPECTED_EDDSA_ED25519_APP_ID,
                precompile_id(&EddsaEd25519Precompile),
            ),
        ] {
            assert_eq!(
                app_id, derived,
                "{name} app_id() literal != precompile_id derivation (got {})",
                app_id.as_canonical_u64(),
            );
            assert_eq!(
                app_id.as_canonical_u64(),
                expected,
                "{name} APP_ID drift — update {name}.masm `const APP_ID` to match (got {})",
                app_id.as_canonical_u64(),
            );
        }

        // Tag-id indices map 1:1 to the MASM `const *_TAG_ID = ...` declarations; pin them so
        // a reorder is caught.
        assert_eq!(Keccak256Precompile::PREIMAGE_TAG_ID, 0);
        assert_eq!(Keccak256Precompile::DIGEST_TAG_ID, 1);
        assert_eq!(Keccak256Precompile::EQ_TAG_ID, 2);
        assert_eq!(Sha512Precompile::PREIMAGE_TAG_ID, 0);
        assert_eq!(Sha512Precompile::DIGEST_TAG_ID, 1);
        assert_eq!(Sha512Precompile::EQ_TAG_ID, 2);
        assert_eq!(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID, 0);
        assert_eq!(EddsaEd25519Precompile::VERIFY_TAG_ID, 0);
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
