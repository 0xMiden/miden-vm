//! Ed25519 base-field domain for the uint precompile.

use miden_core::Felt;

use super::uint::{Limbs, UintSpec};

/// Marker type for the Ed25519 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Base;

impl Ed25519Base {
    /// Modulus of the Ed25519 base field `2^255 - 19`, little-endian u32 limbs.
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
    const ID: Felt = Felt::new_unchecked(5);
    const ENCODED_MODULUS: Limbs = Ed25519Base::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
