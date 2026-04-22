//! Shared field constants for constraint code.

use miden_core::field::PrimeCharacteristicRing;

use crate::Felt;

pub const F_1: Felt = Felt::ONE;
#[allow(dead_code)]
pub const F_NEG_1: Felt = Felt::NEG_ONE;
pub const F_2: Felt = Felt::TWO;
pub const F_3: Felt = Felt::new_unchecked(3);
pub const F_4: Felt = Felt::new_unchecked(4);
pub const F_7: Felt = Felt::new_unchecked(7);
pub const F_8: Felt = Felt::new_unchecked(8);
pub const F_9: Felt = Felt::new_unchecked(9);
pub const F_16: Felt = Felt::new_unchecked(16);
pub const F_27: Felt = Felt::new_unchecked(27);
pub const F_81: Felt = Felt::new_unchecked(81);
pub const F_128: Felt = Felt::new_unchecked(128);
pub const F_243: Felt = Felt::new_unchecked(243);
pub const F_729: Felt = Felt::new_unchecked(729);
pub const F_2187: Felt = Felt::new_unchecked(2187);
pub const TWO_POW_16: Felt = Felt::new_unchecked(1 << 16);
pub const TWO_POW_16_MINUS_1: Felt = Felt::new_unchecked(65535);
pub const TWO_POW_32: Felt = Felt::new_unchecked(1 << 32);
pub const TWO_POW_32_MINUS_1: Felt = Felt::new_unchecked((1u64 << 32) - 1);
pub const TWO_POW_48: Felt = Felt::new_unchecked(1 << 48);
