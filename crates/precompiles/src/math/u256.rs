//! U256 wrapping arithmetic domain for the uint precompile.

use miden_core::{Felt, ZERO};

use crate::math::uint::{Limbs, UintSpec};

/// Marker for arithmetic modulo `2^256`.
#[derive(Debug, Default, Clone, Copy)]
pub struct U256;

impl U256 {
    /// Stable local domain selector carried in uint precompile tags.
    pub const ID: Felt = ZERO;

    /// Encoded modulus sentinel for arithmetic modulo `2^256`.
    pub const ENCODED_MODULUS: Limbs = [0; 8];

    /// Maximum canonical U256 value, `2^256 - 1`.
    pub const MAX: Limbs = [u32::MAX; 8];
}

impl UintSpec for U256 {
    const ID: Felt = Self::ID;
    const ENCODED_MODULUS: Limbs = Self::ENCODED_MODULUS;
}
