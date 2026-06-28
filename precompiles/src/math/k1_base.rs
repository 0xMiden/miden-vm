//! secp256k1 base-field domain for the uint precompile.

use miden_core::Felt;

use super::uint::{Limbs, UintSpec};

/// Marker type for the secp256k1 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct K1Base;

impl K1Base {
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
    const ID: Felt = Felt::new_unchecked(1);
    const ENCODED_MODULUS: Limbs = K1Base::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
