//! Rust reference implementation of Keccak-256, paired with the MASM port at
//! `crates/lib/core/asm/crypto/hashes/keccak256_native.masm` as its comparison
//! target.
//!
//! Two submodules:
//! - [`spec`] holds the FIPS 202 constants (round constants, rho rotation
//!   offsets, lane indexing) used by both the Rust reference and the MASM port,
//!   so a single audit of this file pins both implementations to the same
//!   constants.
//! - [`reference`] is a straight-line Rust implementation of Keccak-f[1600] and
//!   Keccak-256 that mirrors the FIPS 202 pseudocode line-for-line. The MASM
//!   port is differentially tested against it; this reference is itself cross-
//!   checked against [`miden_core::crypto::hash::Keccak256`] via a proptest in
//!   `tests/crypto/keccak256_native.rs`.
//!
//! For most production hashing needs, [`miden_core::crypto::hash::Keccak256`]
//! is the recommended hasher (faster, and the implementation used elsewhere in
//! the codebase).

pub mod reference;
pub mod spec;
