#[cfg(feature = "arbitrary")]
use miden_utils_testing::{MIN_STACK_DEPTH, proptest::prelude::*, rand::rand_vector};

#[test]
fn truncate_stack() {
    let source = "use miden::core::sys begin repeat.12 push.0 end exec.sys::truncate_stack end";
    // Input [1, 2, ..., 16] -> stack with 1 at top
    // After 12 push.0 and truncate: [0, 0, ..., 0, 1, 2, 3, 4]
    build_test!(source, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .expect_stack(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
}

#[test]
fn reduce_kernel_digests_upper_bound() {
    // `stage_reduced_inputs` takes the digest count `N` as an operand and asserts it fits
    // `Kernel::MAX_NUM_PROCEDURES` (`N < 256`). The bound is its first check, so no caller memory
    // or advice is required.
    //
    // Operands: [kernel_ptr, N, stack_io_ptr, PROG0..3].
    let source = "
        use miden::core::sys::vm::public_inputs
        begin
            exec.public_inputs::stage_reduced_inputs
        end
    ";

    let num_kernel_proc_digests = 256_u64; // one over the maximum (255)
    let initial_stack = vec![0_u64, num_kernel_proc_digests, 4096, 1, 2, 3, 4];

    let test = build_test!(source, &initial_stack);
    expect_assert_error_message!(test);
}

#[cfg(feature = "arbitrary")]
proptest! {
    #[test]
    fn truncate_stack_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..100) {
        let push_values = rand_vector::<u64>(n);
        let mut source_vec = vec!["use miden::core::sys".to_string(), "begin".to_string()];
        for value in push_values.iter() {
            source_vec.push(format!("push.{value}"));
        }
        source_vec.push("exec.sys::truncate_stack".to_string());
        source_vec.push("end".to_string());
        let source = source_vec.join(" ");
        let mut expected_values: Vec<u64> = push_values.iter().rev().copied().collect();
        expected_values.extend(test_values.iter());
        expected_values.truncate(MIN_STACK_DEPTH);
        build_test!(&source, &test_values).prop_expect_stack(&expected_values)?;
    }
}
