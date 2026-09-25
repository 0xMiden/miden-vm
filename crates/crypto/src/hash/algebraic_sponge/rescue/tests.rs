#![cfg(feature = "std")]

use super::Felt;

/// S-Box power for Rescue Prime hash function.
const ALPHA: u64 = 7;
/// Inverse S-Box power for Rescue Prime hash function.
const INV_ALPHA: u64 = 10540996611094048183;

#[test]
fn test_alphas() {
    let e: Felt = rand::random::<Felt>();
    let e_exp = e.exp_u64(ALPHA);
    assert_eq!(e, e_exp.exp_u64(INV_ALPHA));
}
