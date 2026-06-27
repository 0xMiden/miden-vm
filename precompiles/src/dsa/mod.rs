//! Digital-signature MASM wrappers built on the native math/hash precompiles.
//!
//! Signature verification in this crate is exposed through MASM modules under
//! `::miden::precompiles::crypto::dsa` rather than through standalone host signature
//! [`Precompile`] implementations.
//!
//! - `ecdsa_secp256k1::assert_verify_prehash` verifies prehashed secp256k1 ECDSA signatures over
//!   native affine public-key coordinates and native scalar limbs.
//! - `eddsa_ed25519::assert_verify` verifies Ed25519/SHA-512 signatures over native affine `A`, a
//!   contiguous native signature buffer `R || S`, and a fixed 32-byte message. The verifier
//!   recompresses `R` and `A` only to form `SHA512(R_compressed || A_compressed || message)`.
//!
//! These wrappers are assert/trap oriented and use the deferred uint/curve/hash precompiles for
//! their semantic checks.
//!
//! [`Precompile`]: miden_core::deferred::Precompile
