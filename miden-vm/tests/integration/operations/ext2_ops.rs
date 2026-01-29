use miden_core::{
    Felt,
    field::{BasedVectorSpace, Field, QuadFelt},
};
use miden_utils_testing::{PrimeField64, build_op_test, rand::rand_quad_felt};

// EXT2 OPS ASSERTIONS - MANUAL TESTS
// ================================================================================================

#[test]
fn ext2add() {
    let asm_op = "ext2add";

    let a = rand_quad_felt();
    let b = rand_quad_felt();
    let c = a + b;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    // Input: [b0, b1, a0, a1] with b0 on top
    let stack_init = [b0, b1, a0, a1];
    // Output: [c0, c1] with c0 on top
    let expected = [c0, c1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2sub() {
    let asm_op = "ext2sub";

    let a = rand_quad_felt();
    let b = rand_quad_felt();
    let c = a - b;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    // Input: [b0, b1, a0, a1] with b0 on top
    let stack_init = [b0, b1, a0, a1];
    let expected = [c0, c1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2mul() {
    let asm_op = "ext2mul";

    let a = rand_quad_felt();
    let b = rand_quad_felt();
    let c = b * a;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    // Input: [b0, b1, a0, a1] with b0 on top
    let stack_init = [b0, b1, a0, a1];
    let expected = [c0, c1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2div() {
    let asm_op = "ext2div";

    let a = rand_quad_felt();
    let b = rand_quad_felt();
    let c = a * b.inverse();
    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    // Input: [b0, b1, a0, a1] with b0 on top
    let stack_init = [b0, b1, a0, a1];
    let expected = [c0, c1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2neg() {
    let asm_op = "ext2neg";

    let a = rand_quad_felt();
    let b = -a;
    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);

    // Input: [a0, a1] with a0 on top
    let stack_init = [a0, a1];
    // Output: [b0, b1] with b0 on top
    let expected = [b0, b1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2inverse() {
    let asm_op = "ext2inv";

    let a = rand_quad_felt();
    let b = a.inverse();

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);

    // Input: [a0, a1] with a0 on top
    let stack_init = [a0, a1];
    let expected = [b0, b1];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

// HELPER FUNCTIONS
// ================================================================================================
/// Helper function to convert a quadratic extension field element into a tuple of elements in the
/// underlying base field and convert them into integers.
fn ext_element_to_ints(ext_elem: QuadFelt) -> (u64, u64) {
    let base_elements: &[Felt] = ext_elem.as_basis_coefficients_slice();
    (base_elements[0].as_canonical_u64(), base_elements[1].as_canonical_u64())
}
