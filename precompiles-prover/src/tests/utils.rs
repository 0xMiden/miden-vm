use miden_core::Felt;

use crate::utils::split_u64;

#[test]
fn split_u64_extracts_lo_hi_halves() {
    assert_eq!(split_u64(0), [Felt::ZERO, Felt::ZERO]);
    // 2^32 → lo = 0, hi = 1.
    assert_eq!(
        split_u64(0x1_0000_0000),
        [Felt::ZERO, Felt::new(1).unwrap()]
    );
    // Max u32 fits in lo.
    assert_eq!(
        split_u64(0xFFFF_FFFF),
        [Felt::new(0xFFFF_FFFF).unwrap(), Felt::ZERO],
    );
    assert_eq!(
        split_u64(0xDEAD_BEEF_CAFE_BABE),
        [
            Felt::new(0xCAFE_BABE).unwrap(),
            Felt::new(0xDEAD_BEEF).unwrap()
        ],
    );
}
