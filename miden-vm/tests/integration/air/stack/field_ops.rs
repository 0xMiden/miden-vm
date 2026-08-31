use miden_core::Felt;
use miden_utils_testing::{PrimeField64, build_op_test};

#[test]
fn incr() {
    let asm_op = "add.1 add.1 push.0 add.1 add.1 eq assert";
    let pub_inputs = vec![0];

    build_op_test!(&asm_op, &pub_inputs).check_constraints();
}

#[test]
fn neg() {
    let asm_op = "dup.0 neg add eq.0 assert";
    let pub_inputs = vec![7];

    build_op_test!(&asm_op, &pub_inputs).check_constraints();
}

#[test]
fn not() {
    let asm_op = "dup.0 not add eq.1 assert";
    let pub_inputs = vec![1];

    build_op_test!(&asm_op, &pub_inputs).check_constraints();
}

#[test]
fn expacc() {
    // Test 9^10.
    let asm_op = "push.10 exp eq.3486784401 assert";
    let pub_inputs = vec![9];

    build_op_test!(&asm_op, &pub_inputs).check_constraints();
}

#[test]
fn bare_exp_constraints_accept_boundaries() {
    for exponent in [0_u64, 1, u32::MAX as u64, 1 << 32, (1 << 63) - 1] {
        let expected = Felt::from_u8(7).exp_u64(exponent).as_canonical_u64();
        let program = format!("exp eq.{expected} assert");
        build_op_test!(&program, &[exponent, 7]).check_constraints();
    }
}

#[test]
fn exp_imm_constraints_accept_full_field_range() {
    for exponent in [1_u64 << 63, Felt::ORDER_U64 - 2, Felt::ORDER_U64 - 1] {
        let expected = Felt::from_u8(7).exp_u64(exponent).as_canonical_u64();
        let program = format!("exp.{exponent} eq.{expected} assert");
        build_op_test!(&program, &[7]).check_constraints();
    }
}
