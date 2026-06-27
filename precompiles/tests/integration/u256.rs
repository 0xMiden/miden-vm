use miden_precompiles::U256;

use crate::uint_fixtures::assert_u256_contract;

const MODULE: &str = "u256";
const U256_MASM: &str = include_str!("../../asm/math/u256.masm");

#[test]
fn u256_satisfies_uint_contract() {
    assert_u256_contract::<U256>(MODULE, U256_MASM);
}
