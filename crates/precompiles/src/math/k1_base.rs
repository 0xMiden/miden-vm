//! secp256k1 base-field domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the secp256k1 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct K1Base;

impl K1Base {
    /// Stable local domain selector carried in uint precompile tags.
    pub const ID: Felt = Felt::new_unchecked(1);

    /// Modulus of the secp256k1 base field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xffff_fc2f,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ];
}

impl UintSpec for K1Base {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
