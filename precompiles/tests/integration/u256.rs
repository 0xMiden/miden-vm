use miden_precompiles::U256;

use crate::uint_fixtures::assert_u256_contract;

const MODULE: &str = "u256";

#[test]
fn u256_satisfies_uint_contract() {
    let u256_masm = miden_precompiles_codegen::masm::render_u256_masm()
        .expect("u256 MASM generation must succeed");
    assert_u256_contract::<U256>(MODULE, &u256_masm);
}
