//! P-256 scalar-field domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the P-256 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct P256Scalar;

impl P256Scalar {
    /// Stable local identifier used for uint-domain metadata.
    pub const ID: Felt = Felt::new_unchecked(8);

    /// Modulus of the P-256 scalar field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xfc63_2551,
        0xf3b9_cac2,
        0xa717_9e84,
        0xbce6_faad,
        0xffff_ffff,
        0xffff_ffff,
        0x0000_0000,
        0xffff_ffff,
    ];
}

impl UintSpec for P256Scalar {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
