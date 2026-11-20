//! Parameter validation and VM AIR-context contracts.

use miden_core::Felt;
use miden_processor::ExecutionOutput;
use rstest::rstest;

use crate::{
    helpers::{read_memory_felt, stark_constant},
    support::security::{
        LOG_HEIGHT_MAX, MVM_LOG_HEIGHT_MIN, NUM_QUERIES_MAX, NUM_QUERIES_MIN, POW_BITS_MAX,
    },
};

mod fold_coefficients;
mod memory_layout;

const LOAD_AIR_CONTEXT: &str = "use miden::core::sys::vm
     begin
         exec.vm::load_air_context
     end";

fn read_memory(output: &ExecutionOutput, addr: u32) -> u64 {
    read_memory_felt(output, addr).as_canonical_u64()
}

fn execute_load_air_context(
    core_log_height: u64,
    chiplets_log_height: u64,
    eidos_compression_log_height: u64,
) -> ExecutionOutput {
    let (output, _) = build_test!(
        LOAD_AIR_CONTEXT,
        &[],
        &[core_log_height, chiplets_log_height, eidos_compression_log_height],
    )
    .execute_for_output()
    .expect("load_air_context should execute");
    assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
    output
}

fn validate_inputs_source(
    num_queries: u64,
    query_pow_bits: u64,
    deep_pow_bits: u64,
    folding_pow_bits: u64,
) -> String {
    format!(
        "use miden::core::stark::utils
         use {{DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR}} from miden::core::stark::constants
         use {{NUM_QUERIES_PTR, QUERY_POW_BITS_PTR}} from miden::core::stark::constants
         begin
             push.{num_queries} mem_store.NUM_QUERIES_PTR
             push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
             push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
             push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
             exec.utils::validate_inputs
         end"
    )
}

#[rstest]
#[case::core_upper([LOG_HEIGHT_MAX + 1, 10, 10])]
#[case::core_lower([MVM_LOG_HEIGHT_MIN - 1, 10, 10])]
#[case::chiplets_upper([10, LOG_HEIGHT_MAX + 1, 10])]
#[case::chiplets_lower([10, MVM_LOG_HEIGHT_MIN - 1, 10])]
#[case::eidos_compression_upper([10, 10, LOG_HEIGHT_MAX + 1])]
#[case::eidos_compression_lower([10, 10, MVM_LOG_HEIGHT_MIN - 1])]
fn load_air_context_rejects_out_of_range_height(#[case] heights: [u64; 3]) {
    let test = build_test!(LOAD_AIR_CONTEXT, &[], &heights);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_accepts_trace_length_boundaries() {
    execute_load_air_context(MVM_LOG_HEIGHT_MIN, MVM_LOG_HEIGHT_MIN, MVM_LOG_HEIGHT_MIN);
    execute_load_air_context(LOG_HEIGHT_MAX, LOG_HEIGHT_MAX, LOG_HEIGHT_MAX);
}

#[test]
fn load_air_context_rejects_a_non_u32_trace_length() {
    let non_u32 = u64::from(u32::MAX) + 1;
    let test = build_test!(LOAD_AIR_CONTEXT, &[], &[non_u32, 10, 10]);
    assert!(test.execute().is_err(), "a non-u32 AIR height must be rejected");
}

#[test]
fn load_air_context_stores_shape_and_max_height() {
    let output = execute_load_air_context(8, 10, 9);
    let heights_ptr = stark_constant("LOG_AIR_TRACE_LENGTHS_PTR");
    for (offset, expected) in [8, 10, 9, 16].into_iter().enumerate() {
        assert_eq!(read_memory(&output, heights_ptr + offset as u32), expected, "AIR {offset}");
    }
    assert_eq!(read_memory(&output, stark_constant("LOG_TRACE_LENGTH_PTR")), 16);
}

#[test]
fn validate_inputs_accepts_num_query_boundaries() {
    for num_queries in [NUM_QUERIES_MIN, NUM_QUERIES_MAX] {
        let source = validate_inputs_source(num_queries, 0, 0, 16);
        build_test!(&source, &[])
            .execute()
            .unwrap_or_else(|err| panic!("num_queries={num_queries} must be accepted: {err}"));
    }
}

#[test]
fn validate_inputs_rejects_num_queries_outside_boundaries() {
    for (num_queries, message) in [
        (NUM_QUERIES_MIN - 1, "num_queries must be at least 7"),
        (NUM_QUERIES_MAX + 1, "num_queries must be at most 150"),
    ] {
        let source = validate_inputs_source(num_queries, 0, 0, 16);
        let test = build_test!(&source, &[]);
        expect_assert_error_code_from_msg!(test, message);
    }
}

#[test]
fn validate_inputs_pow_bit_bounds() {
    for (name, valid, invalid, message) in [
        (
            "query_pow_bits",
            [POW_BITS_MAX, 0, 0],
            [POW_BITS_MAX + 1, 0, 0],
            "query_pow_bits must be less than 32",
        ),
        (
            "deep_pow_bits",
            [0, POW_BITS_MAX, 0],
            [0, POW_BITS_MAX + 1, 0],
            "deep_pow_bits must be less than 32",
        ),
        (
            "folding_pow_bits",
            [0, 0, POW_BITS_MAX],
            [0, 0, POW_BITS_MAX + 1],
            "folding_pow_bits must be less than 32",
        ),
    ] {
        let [query, deep, folding] = valid;
        let source = validate_inputs_source(27, query, deep, folding);
        build_test!(&source, &[])
            .execute()
            .unwrap_or_else(|err| panic!("{name}={POW_BITS_MAX} must be accepted: {err}"));

        let [query, deep, folding] = invalid;
        let source = validate_inputs_source(27, query, deep, folding);
        let test = build_test!(&source, &[]);
        expect_assert_error_code_from_msg!(test, message);
    }
}

#[test]
fn validate_inputs_processor_rejects_non_u32_security_parameters() {
    let non_u32 = u64::from(u32::MAX) + 1;
    for [num_queries, query, deep, folding] in [
        [non_u32, 0, 0, 0],
        [27, non_u32, 0, 0],
        [27, 0, non_u32, 0],
        [27, 0, 0, non_u32],
    ] {
        let source = validate_inputs_source(num_queries, query, deep, folding);
        let test = build_test!(&source, &[]);
        assert!(test.execute().is_err(), "a non-u32 security parameter must be rejected");
    }
}

#[test]
fn init_seed_trace_length_too_large_has_message() {
    // A trace length of 2^32 fails init_seed's u32 range check.
    let source = "
        use {RELATION_DIGEST_PTR, LOG_TRACE_LENGTH_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin
        begin
            push.32 mem_store.LOG_TRACE_LENGTH_PTR
            push.0.0.0.0 mem_storew_le.RELATION_DIGEST_PTR dropw
            exec.random_coin::init_seed
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
        use {DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR} from miden::core::stark::constants
        use {NUM_QUERIES_PTR, QUERY_POW_BITS_PTR} from miden::core::stark::constants
        use {RELATION_DIGEST_PTR, LOG_TRACE_LENGTH_PTR} from miden::core::stark::constants
        begin
            push.27 mem_store.NUM_QUERIES_PTR
            push.16 mem_store.QUERY_POW_BITS_PTR
            push.0  mem_store.DEEP_POW_BITS_PTR
            push.16 mem_store.FOLDING_POW_BITS_PTR
            push.10 mem_store.LOG_TRACE_LENGTH_PTR
            push.0.0.0.0 mem_storew_le.RELATION_DIGEST_PTR dropw
            exec.random_coin::init_seed
            exec.random_coin::check_query_pow
        end
    ";
    let advice_stack = &[0_u64];
    let test = build_test!(source, &[], advice_stack);
    expect_assert_error_message!(test);
}

/// Proof ordering and selector setup read the height array in canonical AIR order.
#[test]
fn relation_height_initialization_writes_the_generic_array_in_order() {
    let source = "use miden::core::sys::vm::layout
     begin
         push.11 exec.layout::set_core_trace_length_log
         push.22 exec.layout::set_chiplets_trace_length_log
         push.33 exec.layout::set_eidos_compression_trace_length_log
         exec.layout::init_and8_lookup_trace_length_log
     end";
    let (output, _) = build_test!(source, &[])
        .execute_for_output()
        .expect("height initialization should execute");
    let heights_ptr = stark_constant("LOG_AIR_TRACE_LENGTHS_PTR");
    for (offset, expected) in [11, 22, 33, 16].into_iter().enumerate() {
        assert_eq!(read_memory(&output, heights_ptr + offset as u32), expected, "AIR {offset}");
    }
}

/// Loading advice into the AIR context must preserve the caller's operand stack.
#[test]
fn vm_wrapper_preserves_the_caller_stack() {
    const SENTINELS: [u64; 8] = [16_201, 16_202, 16_203, 16_204, 16_205, 16_206, 16_207, 16_208];
    let (control, _) = build_test!("begin push.0 drop end", &SENTINELS)
        .execute_for_output()
        .expect("control program must run");
    let (subject, _) = build_test!(LOAD_AIR_CONTEXT, &SENTINELS, &[16, 16, 16])
        .execute_for_output()
        .expect("VM AIR context must load");

    assert_eq!(
        subject.stack.get_num_elements(16),
        control.stack.get_num_elements(16),
        "load_air_context must leave the caller stack unchanged"
    );
}
