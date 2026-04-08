//! Shared field constants for constraint code.

use miden_core::field::PrimeCharacteristicRing;

use crate::Felt;

pub const F_1: Felt = Felt::ONE;
#[allow(dead_code)]
pub const F_NEG_1: Felt = Felt::NEG_ONE;
pub const F_2: Felt = Felt::TWO;
pub const F_3: Felt = Felt::new(3);
pub const F_4: Felt = Felt::new(4);
pub const F_5: Felt = Felt::new(5);
pub const F_6: Felt = Felt::new(6);
pub const F_7: Felt = Felt::new(7);
pub const F_8: Felt = Felt::new(8);
pub const F_9: Felt = Felt::new(9);
pub const F_16: Felt = Felt::new(16);
pub const F_27: Felt = Felt::new(27);
pub const F_81: Felt = Felt::new(81);
pub const F_128: Felt = Felt::new(128);
pub const F_243: Felt = Felt::new(243);
pub const F_729: Felt = Felt::new(729);
pub const F_2187: Felt = Felt::new(2187);
pub const TWO_POW_16: Felt = Felt::new(1 << 16);
pub const TWO_POW_16_MINUS_1: Felt = Felt::new(65535);
pub const TWO_POW_32: Felt = Felt::new(1 << 32);
pub const TWO_POW_32_MINUS_1: Felt = Felt::new((1u64 << 32) - 1);
pub const TWO_POW_48: Felt = Felt::new(1 << 48);
