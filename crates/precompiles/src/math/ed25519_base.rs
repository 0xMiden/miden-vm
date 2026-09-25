//! Ed25519 base-field domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the Ed25519 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Base;

impl Ed25519Base {
    /// Stable local domain selector carried in uint precompile tags.
    pub const ID: Felt = Felt::new_unchecked(4);

    /// Modulus of the Ed25519 base field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xffff_ffed,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0x7fff_ffff,
    ];
}

impl UintSpec for Ed25519Base {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
