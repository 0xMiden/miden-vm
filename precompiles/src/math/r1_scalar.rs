//! secp256r1 scalar-field domain for the uint precompile.

use miden_core::Felt;

use super::uint::{Limbs, UintSpec};

/// Marker type for the secp256r1 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct R1Scalar;

impl R1Scalar {
    /// Modulus of the secp256r1 scalar field, little-endian u32 limbs.
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

impl UintSpec for R1Scalar {
    const ID: Felt = Felt::new_unchecked(4);
    const ENCODED_MODULUS: Limbs = R1Scalar::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}
