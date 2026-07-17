//! Field/hash configuration modules for testing.
//!
//! Each module provides complete type aliases, constructors, and helpers
//! for testing at any level (LMCS, PCS, or full STARK).
//!
//! The common field types (`Felt`, `QuadFelt`, `PackedFelt`) are defined here
//! and re-exported by each hash configuration module.

use p3_field::{Field, extension::BinomialExtensionField};
use p3_goldilocks::Goldilocks;

/// Goldilocks base field.
pub type Felt = Goldilocks;

/// Quadratic extension of Goldilocks.
pub type QuadFelt = BinomialExtensionField<Felt, 2>;

/// Packed base field for SIMD operations.
pub type PackedFelt = <Felt as Field>::Packing;

#[cfg(feature = "testing")]
pub mod goldilocks_blake3;
#[cfg(feature = "testing")]
pub mod goldilocks_blake3_192;
#[cfg(feature = "testing")]
pub mod goldilocks_keccak;
pub mod goldilocks_poseidon2;
