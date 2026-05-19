//! Core precompiles that back the MASM wrappers in `asm/crypto/`.
//!
//! Each precompile is a self-contained [`Precompile`] implementation in its own file, paired
//! with the MASM wrapper that emits its tags via the deferred-DAG `sys::register_*` /
//! `sys::evaluate` events. The composite [`PrecompileRegistry`] returned by [`registry`] routes
//! tags to the right precompile by id.
//!
//! - [`keccak256`] — Keccak256 preimage / digest / eq.
//! - [`sha512`] — SHA-512 preimage / digest / eq.
//! - [`ecdsa_k256_keccak`] — ECDSA secp256k1 / Keccak256 prehash verify.
//! - [`eddsa_ed25519`] — Ed25519 / SHA-512 verify (with externally supplied `k_digest`).
//!
//! [`Precompile`]: miden_core::deferred::Precompile
//! [`PrecompileRegistry`]: miden_core::deferred::PrecompileRegistry

mod codec;

pub mod ecdsa_k256_keccak;
pub mod eddsa_ed25519;
pub mod keccak256;
pub mod sha512;

pub use codec::{BYTES_PER_CHUNK, n_chunks};
pub use ecdsa_k256_keccak::EcdsaK256KeccakPrecompile;
pub use eddsa_ed25519::EddsaEd25519Precompile;
pub use keccak256::Keccak256Precompile;
use miden_core::deferred::PrecompileRegistry;
pub use sha512::Sha512Precompile;

/// Build the composite [`PrecompileRegistry`] hosting all four core precompiles.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::default()
        .with_precompile(Keccak256Precompile)
        .with_precompile(Sha512Precompile)
        .with_precompile(EcdsaK256KeccakPrecompile)
        .with_precompile(EddsaEd25519Precompile)
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    /// Emits each precompile's derived `id` so the MASM mirror (`const PRECOMPILE_ID = …` in the
    /// matching `.masm`) can be kept in sync. Run with `cargo test -- --nocapture` to see the
    /// values when updating MASM after a rename or derivation change.
    #[test]
    fn emit_masm_pinned_ids() {
        std::println!("MASM const PRECOMPILE_ID per precompile (Blake3 derivation over NAME):");
        for (name, id) in [
            ("keccak256        ", Keccak256Precompile::id()),
            ("sha512           ", Sha512Precompile::id()),
            ("ecdsa_k256_keccak", EcdsaK256KeccakPrecompile::id()),
            ("eddsa_ed25519    ", EddsaEd25519Precompile::id()),
        ] {
            std::println!("  {name} = {}", id.as_canonical_u64());
        }
        // Tag-id indices are mirrored as MASM `const *_TAG_ID = ...` — pin them so a reorder is
        // caught at build time.
        assert_eq!(Keccak256Precompile::PREIMAGE_TAG_ID, 0);
        assert_eq!(Keccak256Precompile::DIGEST_TAG_ID, 1);
        assert_eq!(Keccak256Precompile::EQ_TAG_ID, 2);
        assert_eq!(Sha512Precompile::PREIMAGE_TAG_ID, 0);
        assert_eq!(Sha512Precompile::DIGEST_TAG_ID, 1);
        assert_eq!(Sha512Precompile::EQ_TAG_ID, 2);
        assert_eq!(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID, 0);
        assert_eq!(EddsaEd25519Precompile::VERIFY_TAG_ID, 0);
    }
}
