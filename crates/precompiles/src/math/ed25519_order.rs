//! Ed25519 full-group-order domain for the uint precompile.

use miden_core::Felt;

use crate::math::uint::{Limbs, UintSpec};

/// Marker type for the full Ed25519 group order `8*l`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Order;

impl Ed25519Order {
    /// Stable local domain selector carried in uint precompile tags.
    pub const ID: Felt = Felt::new_unchecked(6);

    /// Full Ed25519 group order `8*l`, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xe7ae_9f68,
        0xc093_18d2,
        0x17bc_e6b2,
        0xa6f7_cef5,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x8000_0000,
    ];
}

impl UintSpec for Ed25519Order {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::MODULUS;
}
