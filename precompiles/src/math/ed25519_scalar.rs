//! Ed25519 scalar-field domain for the uint precompile.

use miden_core::Felt;

use super::uint::{Limbs, UintSpec};

/// Marker type for the Ed25519 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Scalar;

impl Ed25519Scalar {
    /// Modulus of the Ed25519 scalar field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0x5cf5_d3ed,
        0x5812_631a,
        0xa2f7_9cd6,
        0x14de_f9de,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x1000_0000,
    ];
}

impl UintSpec for Ed25519Scalar {
    const ID: Felt = Felt::new_unchecked(6);
    const ENCODED_MODULUS: Limbs = Ed25519Scalar::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
