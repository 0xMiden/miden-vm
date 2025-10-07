use miden_core::{Field, QuadFelt};
use miden_utils_testing::{build_op_test, rand::rand_value};

// EXT2 OPS ASSERTIONS - MANUAL TESTS
// ================================================================================================

#[test]
fn ext2add() {
    let asm_op = "ext2add";

    let a = rand_value::<QuadFelt>();
    let b = rand_value::<QuadFelt>();
    let c = a + b;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    let stack_init = [a0, a1, b0, b1];
    let expected = [c1, c0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2sub() {
    let asm_op = "ext2sub";

    let a = rand_value::<QuadFelt>();
    let b = rand_value::<QuadFelt>();
    let c = a - b;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    let stack_init = [a0, a1, b0, b1];
    let expected = [c1, c0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2mul() {
    let asm_op = "ext2mul";

    let a = rand_value::<QuadFelt>();
    let b = rand_value::<QuadFelt>();
    let c = b * a;

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    let stack_init = [a0, a1, b0, b1];
    let expected = [c1, c0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2div() {
    let asm_op = "ext2div";

    let a = rand_value::<QuadFelt>();
    let b = rand_value::<QuadFelt>();
    let c = a * b.inverse();
    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);
    let (c0, c1) = ext_element_to_ints(c);

    let stack_init = [a0, a1, b0, b1];
    let expected = [c1, c0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2neg() {
    let asm_op = "ext2neg";

    let a = rand_value::<QuadFelt>();
    let b = -a;
    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);

    let stack_init = [a0, a1];
    let expected = [b1, b0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

#[test]
fn ext2inverse() {
    let asm_op = "ext2inv";

    let a = rand_value::<QuadFelt>();
    let b = a.inverse();

    let (a0, a1) = ext_element_to_ints(a);
    let (b0, b1) = ext_element_to_ints(b);

    let stack_init = [a0, a1];
    let expected = [b1, b0];

    let test = build_op_test!(asm_op, &stack_init);
    test.expect_stack(&expected);
}

// HELPER FUNCTIONS
// ================================================================================================
/// Helper function to convert a quadratic extension field element into a tuple of elements in the
/// underlying base field and convert them into integers.
fn ext_element_to_ints(ext_elem: QuadFelt) -> (u64, u64) {
    let base_elements = ext_elem.to_array();
    (base_elements[0].as_int(), base_elements[1].as_int())
}
