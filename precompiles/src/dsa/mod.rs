//! Digital-signature MASM wrappers built on the native math/hash precompiles.
//!
//! Signature verification in this crate is implemented by MASM support modules rather than by
//! standalone host signature [`Precompile`] implementations.
//!
//! - `ecdsa_secp256k1::assert_verify_prehash` verifies prehashed secp256k1 ECDSA signatures over
//!   native affine public-key coordinates and native scalar limbs.
//!
//! These wrappers are assert/trap oriented and use the uint/curve/hash precompiles for their
//! semantic checks.
//!
//! [`Precompile`]: miden_core::deferred::Precompile
