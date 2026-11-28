use miden_core::field::Field;
use miden_utils_testing::{Felt, PrimeField64, build_test};

/// A field instruction that accepts an immediate operand must be listed in this test.
#[test]
fn field_immediates_match_push_forms_on_the_full_stack() {
    let mut inputs: Vec<u64> = (1..=16).collect();
    // Immediates with a dedicated lowering, their neighbours, and one wider than 32 bits.
    let immediates = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 1_u64 << 32];
    // As bases of `exp`, 0, 1 and p - 1 reveal only whether the exponent is zero and its parity; a
    // generator of the multiplicative group separates the exponents.
    let values = [0, 1, Felt::GENERATOR.as_canonical_u64(), Felt::ORDER_U64 - 1];
    for op in ["add", "sub", "mul", "div", "exp", "eq", "neq", "lt", "lte", "gt", "gte"] {
        for imm in immediates {
            // The assembler rejects division by a zero immediate.
            if op == "div" && imm == 0 {
                continue;
            }
            for value in values {
                inputs[0] = value;
                assert_immediate_form_matches_push_form(op, imm, "", &inputs);
            }
        }
    }
}

/// A u32 instruction that accepts an immediate operand must be listed in one of the tables below.
///
/// A form that assembles to `push.b` followed by the instruction compares two identical programs.
/// It is listed so that a dedicated lowering, if one is added, is compared with the push form.
#[test]
fn u32_immediates_match_push_forms_on_the_full_stack() {
    const MAX: u64 = u32::MAX as u64;
    // Instructions that replace one value with one result.
    let single_result: &[(&str, &[u64])] = &[
        ("u32wrapping_add", &[0, 1, 2, MAX]),
        ("u32wrapping_sub", &[0, 1, 2, MAX]),
        ("u32wrapping_mul", &[0, 1, 2, MAX]),
        // The assembler rejects a zero divisor.
        ("u32div", &[1, 2, MAX]),
        ("u32mod", &[1, 2, MAX]),
        ("u32and", &[0, 1, MAX]),
        ("u32or", &[0, 1, MAX]),
        ("u32xor", &[0, 1, MAX]),
        // Shift and rotation amounts are limited to 31.
        ("u32shl", &[0, 1, 31]),
        ("u32shr", &[0, 1, 31]),
        ("u32rotl", &[0, 1, 31]),
        ("u32rotr", &[0, 1, 31]),
        ("u32lt", &[0, 1, MAX]),
        ("u32lte", &[0, 1, MAX]),
        ("u32gt", &[0, 1, MAX]),
        ("u32gte", &[0, 1, MAX]),
        ("u32min", &[0, 1, MAX]),
        ("u32max", &[0, 1, MAX]),
    ];
    // Instructions that leave one more value than they consume. Each tail drops one of the top
    // two values to return to the minimum stack depth, so the two tails together compare both.
    let one_more_value: &[(&str, &[u64])] = &[
        ("u32overflowing_add", &[0, 1, 2, MAX]),
        ("u32overflowing_sub", &[0, 1, 2, MAX]),
        ("u32widening_add", &[0, 1, 2, MAX]),
        ("u32widening_mul", &[0, 1, 2, MAX]),
        ("u32divmod", &[1, 2, MAX]),
        ("u32not", &[0, 1, MAX]),
    ];

    let mut inputs: Vec<u64> = (1..=16).collect();
    for value in [0, 1, MAX] {
        inputs[0] = value;
        for &(op, immediates) in single_result {
            for &imm in immediates {
                assert_immediate_form_matches_push_form(op, imm, "", &inputs);
            }
        }
        for &(op, immediates) in one_more_value {
            for &imm in immediates {
                assert_immediate_form_matches_push_form(op, imm, "drop", &inputs);
                assert_immediate_form_matches_push_form(op, imm, "swap drop", &inputs);
            }
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Asserts that `{op}.{imm}` and `push.{imm} {op}` leave the same operand stack when each is
/// followed by `tail` and run on `inputs`.
///
/// Programs start at the minimum stack depth of 16. Pass distinct non-zero values below the
/// operand so that a shifted stack shows in the output. The programs run without the stack
/// truncation that `build_op_test!` appends, so a final depth above 16 makes execution fail. `tail`
/// restores the depth for instructions that leave more values than they consume.
#[track_caller]
fn assert_immediate_form_matches_push_form(op: &str, imm: u64, tail: &str, inputs: &[u64]) {
    let stack_after = |source: &str| {
        build_test!(source, inputs)
            .execute_for_output()
            .map(|(output, _)| output.stack)
            .map_err(|err| err.to_string())
    };

    let push_form = format!("begin push.{imm} {op} {tail} end");
    let immediate_form = format!("begin {op}.{imm} {tail} end");
    let expected = match stack_after(&push_form) {
        Ok(stack) => stack,
        Err(err) => panic!("`{push_form}` failed on {inputs:?}: {err}"),
    };
    assert_eq!(
        stack_after(&immediate_form),
        Ok(expected),
        "`{immediate_form}` and `{push_form}` disagree on {inputs:?}",
    );
}
