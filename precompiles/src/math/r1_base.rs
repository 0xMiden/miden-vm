//! secp256r1 base-field domain for the uint precompile.

use miden_core::Felt;

use super::uint::{Limbs, UintSpec};

/// Marker type for the secp256r1 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct R1Base;

impl R1Base {
    /// Modulus of the secp256r1 base field, little-endian u32 limbs.
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

impl UintSpec for R1Base {
    const ID: Felt = Felt::new_unchecked(3);
    const ENCODED_MODULUS: Limbs = R1Base::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
