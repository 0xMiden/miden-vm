// ---- validate_inputs tests ----
//
// validate_inputs reads `log(core_trace_length)` and `log(chiplets_trace_length)`
// from the stack (caller order) and security parameters (num_queries,
// query_pow_bits, deep_pow_bits, folding_pow_bits) from memory. Tests must store
// the parameters in memory before calling validate_inputs.

fn validate_inputs_source(
    log_core_tl: u32,
    log_chiplets_tl: u32,
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
             push.{log_chiplets_tl} push.{log_core_tl}
             exec.utils::validate_inputs
         end"
    )
}

#[test]
fn validate_inputs_core_trace_length_upper_bound() {
    // log(core_trace_length) = 30 must be rejected (must be < 30); chiplets ok.
    let source = validate_inputs_source(30, 10, 27, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_core_trace_length_lower_bound() {
    // log(core_trace_length) = 5 must be rejected (must be > 5); chiplets ok.
    let source = validate_inputs_source(5, 10, 27, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_chiplets_trace_length_upper_bound() {
    // log(chiplets_trace_length) = 30 must be rejected; core ok.
    let source = validate_inputs_source(10, 30, 27, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_chiplets_trace_length_lower_bound() {
    // log(chiplets_trace_length) = 5 must be rejected; core ok.
    let source = validate_inputs_source(10, 5, 27, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_num_queries_upper_bound() {
    // num_queries = 151 must be rejected (must be < 151); heights are valid.
    let source = validate_inputs_source(10, 10, 151, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_num_queries_lower_bound() {
    // num_queries = 6 must be rejected (must be > 6); heights are valid.
    let source = validate_inputs_source(10, 10, 6, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_grinding_upper_bound() {
    // folding_pow_bits = 32 must be rejected (must be < 32); heights are valid.
    let source = validate_inputs_source(10, 10, 27, 0, 0, 32);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

// ---- init_seed tests ----
//
// init_seed expects:
//   Stack: [log(core_trace_length), log(chiplets_trace_length), rd0, rd1, rd2, rd3, ...]
//   Memory: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits

#[test]
fn init_seed_trace_length_too_large_has_message() {
    // log(core_trace_length) = 32 overflows u32 at pow2 (in init_seed's
    // `pow2` step that derives the trace length), triggering an assertion.
    // chiplets_trace_length is valid (10).
    let source = "
        use miden::core::stark::random_coin
        begin
            push.0.0.0.0 push.10 push.32
            exec.random_coin::init_seed
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn check_pow_invalid_has_message() {
    // Store query_pow_bits = 16 so check_pow actually exercises the PoW path.
    // Use valid per-AIR log heights = 10 so init_seed succeeds.
    // The advice nonce (0) will fail the PoW check.
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.0  exec.constants::set_deep_pow_bits
            push.16 exec.constants::set_folding_pow_bits
            push.0.0.0.0 push.10 push.10
            exec.random_coin::init_seed
            exec.random_coin::check_query_pow
        end
    ";
    let advice_stack = &[0_u64];
    let test = build_test!(source, &[], advice_stack);
    expect_assert_error_message!(test);
}
