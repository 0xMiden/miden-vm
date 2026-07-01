// ---- AIR context and validate_inputs tests ----
//
// The VM wrapper validates AIR shape before calling the generic verifier. The generic
// validate_inputs procedure only checks memory-resident security parameters.

use miden_core::Felt;
use miden_processor::{ContextId, ExecutionOutput};

const TRACE_LENGTH_LOG_PTR: u32 = 3223322634;
const CORE_TRACE_LENGTH_LOG_PTR: u32 = 3223322635;
const CHIPLETS_TRACE_LENGTH_LOG_PTR: u32 = 3223322636;
const POSEIDON2_PERMUTATION_TRACE_LENGTH_LOG_PTR: u32 = 3223322637;
const ORDER_TAG_PTR: u32 = 3223322764;

fn load_air_context_source() -> &'static str {
    "use miden::core::sys::vm
     begin
         exec.vm::load_air_context
     end"
}

fn read_memory(output: &ExecutionOutput, addr: u32) -> u64 {
    output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(addr))
        .unwrap_or_else(|_| panic!("memory address {addr} was not written"))
        .as_canonical_u64()
}

fn execute_load_air_context(
    core_log_height: u64,
    chiplets_log_height: u64,
    poseidon2_log_height: u64,
) -> ExecutionOutput {
    let (output, _) = build_test!(
        load_air_context_source(),
        &[],
        &[core_log_height, chiplets_log_height, poseidon2_log_height],
    )
    .execute_for_output()
    .expect("load_air_context should execute");
    assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
    output
}

fn validate_inputs_source(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
) -> String {
    format!(
        "use miden::core::stark::utils
         use miden::core::stark::constants
         begin
             push.{num_queries} exec.constants::set_number_queries
             push.{query_pow_bits} exec.constants::set_query_pow_bits
             push.{deep_pow_bits} exec.constants::set_deep_pow_bits
             push.{folding_pow_bits} exec.constants::set_folding_pow_bits
             exec.utils::validate_inputs
         end"
    )
}

#[test]
fn load_air_context_core_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[30, 10, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_core_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[5, 10, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 30, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 5, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_poseidon2_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, 30]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_poseidon2_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, 5]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_stores_shape_and_max_height() {
    let output = execute_load_air_context(8, 10, 9);
    assert_eq!(read_memory(&output, CORE_TRACE_LENGTH_LOG_PTR), 8);
    assert_eq!(read_memory(&output, CHIPLETS_TRACE_LENGTH_LOG_PTR), 10);
    assert_eq!(read_memory(&output, POSEIDON2_PERMUTATION_TRACE_LENGTH_LOG_PTR), 9);
    assert_eq!(read_memory(&output, TRACE_LENGTH_LOG_PTR), 10);
}

#[test]
fn load_air_context_derives_proof_order_tags() {
    let cases = [
        ((8, 9, 10), 0), // Core, Chiplets, Poseidon2Permutation
        ((8, 10, 9), 1), // Core, Poseidon2Permutation, Chiplets
        ((9, 8, 10), 2), // Chiplets, Core, Poseidon2Permutation
        ((10, 8, 9), 3), // Chiplets, Poseidon2Permutation, Core
        ((9, 10, 8), 4), // Poseidon2Permutation, Core, Chiplets
        ((10, 9, 8), 5), // Poseidon2Permutation, Chiplets, Core
        ((8, 8, 8), 0),  // ties use instance order
    ];

    for ((core, chiplets, poseidon2), expected_tag) in cases {
        let output = execute_load_air_context(core, chiplets, poseidon2);
        assert_eq!(read_memory(&output, ORDER_TAG_PTR), expected_tag);
    }
}

#[test]
fn validate_inputs_num_queries_upper_bound() {
    // num_queries = 151 must be rejected (must be < 151).
    let source = validate_inputs_source(151, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_num_queries_lower_bound() {
    // num_queries = 6 must be rejected (must be > 6).
    let source = validate_inputs_source(6, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_grinding_upper_bound() {
    // folding_pow_bits = 32 must be rejected (must be < 32).
    let source = validate_inputs_source(27, 0, 0, 32);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

// ---- init_seed tests ----
//
// init_seed expects:
//   Memory: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, relation digest,
//           and trace-height metadata.

#[test]
fn init_seed_trace_length_too_large_has_message() {
    // log(trace_length) = 32 overflows u32 in init_seed's `pow2` step.
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        begin
            push.32 exec.constants::set_trace_length_log
            push.0.0.0.0 exec.constants::relation_digest_ptr mem_storew_le dropw
            exec.random_coin::init_seed
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn generate_aux_randomness_mismatch_has_message() {
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        begin
            push.11.22.33.44 exec.constants::r1_ptr mem_storew_be dropw
            push.99.44.11.22 exec.constants::aux_rand_nd_ptr mem_storew_be dropw
            exec.random_coin::generate_aux_randomness
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn check_pow_invalid_has_message() {
    // Store query_pow_bits = 16 so check_pow actually exercises the PoW path.
    // Use a valid trace height so init_seed succeeds.
    // The advice nonce (0) will fail the PoW check.
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.0  exec.constants::set_deep_pow_bits
            push.16 exec.constants::set_folding_pow_bits
            push.10 exec.constants::set_trace_length_log
            push.0.0.0.0 exec.constants::relation_digest_ptr mem_storew_le dropw
            exec.random_coin::init_seed
            exec.random_coin::check_query_pow
        end
    ";
    let advice_stack = &[0_u64];
    let test = build_test!(source, &[], advice_stack);
    expect_assert_error_message!(test);
}
