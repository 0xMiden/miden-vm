//! P-256 base-field domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the P-256 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct P256Base;

impl P256Base {
    /// Stable local identifier used for uint-domain metadata.
    pub const ID: Felt = Felt::new_unchecked(7);

    /// Modulus of the P-256 base field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x0000_0001,
        0xffff_ffff,
    ];
}

impl UintSpec for P256Base {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
