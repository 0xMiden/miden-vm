use miden_core::WORD_SIZE;
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
    // init_seed contract:
    //   Stack: [log(core_trace_length), log(chiplets_trace_length), rd0, rd1, rd2, rd3, ...]
    //   Memory: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits
    //
    // process_public_inputs advice stack (consumed in order):
    //   1. load_public_inputs: 40 fixed-length PI felts (5 iterations of 8)
    //   2. reduce_variable_length_public_inputs:
    //        - 1 felt (num_kernel_proc_digests)
    //        - num_kernel_proc_digests * 8 felts (digests via adv_pipe)
    //        - 4 felts (aux randomness via adv_loadw)
    //   3. reduce_kernel_digests asserts num_kernel_proc_digests < 1024
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs
        begin
            push.27 exec.constants::set_number_queries
            push.0  exec.constants::set_query_pow_bits
            push.0  exec.constants::set_deep_pow_bits
            push.16 exec.constants::set_folding_pow_bits
            push.0.0.0.0 push.10 push.10
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
    ";

    let num_kernel_proc_digests = 1024_usize;
    let num_elements_kernel_proc_digests = num_kernel_proc_digests * WORD_SIZE.next_multiple_of(8);
    let fixed_length_public_inputs = vec![0_u64; 40];
    let kernel_procedures_digests = vec![0_u64; num_elements_kernel_proc_digests];
    let auxiliary_rand_values = [0_u64; 4];

    // Advice layout (consumed top-to-bottom):
    //   40 fixed-len PI, 1 num_kernel_proc_digests, 8192 digest felts, 4 aux rand
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&fixed_length_public_inputs);
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    let test = build_test!(source, &[], &advice_stack);
    expect_assert_error_message!(test);
}

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
