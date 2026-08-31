//! secp256k1 scalar-field domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the secp256k1 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct K1Scalar;

impl K1Scalar {
    /// Stable local domain selector carried in uint precompile tags.
    pub const ID: Felt = Felt::new_unchecked(2);

    /// Modulus of the secp256k1 scalar field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xd036_4141,
        0xbfd2_5e8c,
        0xaf48_a03b,
        0xbaae_dce6,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ];
}

impl UintSpec for K1Scalar {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
