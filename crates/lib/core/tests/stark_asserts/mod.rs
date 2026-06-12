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

const FRI_PREPROCESS_SOURCE: &str = "
    use miden::core::stark::constants

    const MAX_FRI_QUERIES = 150
    const MAX_FRI_LAYERS = 32
    const MAX_FRI_REMAINDER_WORDS = 64

    proc preprocess
        adv_push
        # => [num_queries, g, ...]
        dup u32gt.0 assert.err=\"number of FRI queries must be nonzero\"
        dup u32lte.MAX_FRI_QUERIES assert.err=\"number of FRI queries exceeds FRI workspace\"

        exec.constants::fri_com_ptr
        # => [layer_ptr, num_queries, g, ...]
        dup.1 mul.4 sub
        # => [query_ptr, num_queries, g, ...]
        dup exec.constants::set_fri_queries_address
        swap
        sub.1
        padw
        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
        #=> [X, x, layer_ptr, g]

        drop
        #=> [X, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, layer_ptr, layer_ptr, g]

        adv_push
        dup u32lte.MAX_FRI_LAYERS assert.err=\"number of FRI layers exceeds FRI workspace\"

        dup push.0 neq
        if.true
            mul.2
            sub.1
            movdn.4
            #=> [X, num_layers, layer_ptr, layer_ptr, g]

            push.1
            while.true
                adv_loadw
                dup.5
                u32wrapping_add.4
                swap.6
                mem_storew_le
                dup.4
                sub.1
                swap.5
                neq.0
            end
            #=> [X, x, remainder_poly_ptr, layer_ptr, g]

            drop
        else
            drop
        end
        #=> [X, remainder_poly_ptr, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        adv_push
        dup u32gt.0 assert.err=\"FRI remainder polynomial must be nonzero\"
        dup u32lte.MAX_FRI_REMAINDER_WORDS assert.err=\"FRI remainder polynomial exceeds FRI workspace\"

        dup mul.2 exec.constants::set_remainder_poly_size

        sub.1
        movdn.4
        #=> [X, len_remainder/2, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
        #=> [X, x, x, remainder_poly_ptr, layer_ptr, g]
        dropw drop drop
        #=> [remainder_poly_ptr, layer_ptr, g]

        exec.constants::set_remainder_poly_address
        drop drop
    end
";

fn fri_preprocess_source(body: &str) -> String {
    format!(
        "{FRI_PREPROCESS_SOURCE}
         begin
             {body}
         end"
    )
}

#[test]
fn fri_preprocess_rejects_oversized_query_count() {
    let source = fri_preprocess_source("exec.preprocess");
    let advice_stack = build_preprocess_advice_stack(151, 0, 0);
    let test = build_test!(&source, &[1], &advice_stack);
    expect_assert_error_message!(test, contains "number of FRI queries exceeds FRI workspace");
}

#[test]
fn fri_preprocess_rejects_oversized_layer_count() {
    let source = fri_preprocess_source("exec.preprocess");
    let advice_stack = build_preprocess_advice_stack(1, 33, 0);
    let test = build_test!(&source, &[1], &advice_stack);
    expect_assert_error_message!(test, contains "number of FRI layers exceeds FRI workspace");
}

#[test]
fn fri_preprocess_rejects_oversized_remainder() {
    let source = fri_preprocess_source("exec.preprocess");
    let advice_stack = build_preprocess_advice_stack(1, 1, 65);
    let test = build_test!(&source, &[1], &advice_stack);
    expect_assert_error_message!(test, contains "FRI remainder polynomial exceeds FRI workspace");
}

#[test]
fn fri_preprocess_rejects_zero_counts() {
    let source = fri_preprocess_source("exec.preprocess");

    let test = build_test!(&source, &[1], &build_preprocess_advice_stack(0, 1, 1));
    expect_assert_error_message!(test, contains "number of FRI queries must be nonzero");

    let test = build_test!(&source, &[1], &build_preprocess_advice_stack(1, 1, 0));
    expect_assert_error_message!(test, contains "FRI remainder polynomial must be nonzero");
}

#[test]
fn fri_preprocess_accepts_zero_layers() {
    const VICTIM_ADDR: u32 = 0;
    const VICTIM_WORD: [u64; 4] = [91, 92, 93, 94];

    let source = fri_preprocess_source(
        "
        push.[91,92,93,94] push.0 mem_storew_le dropw
        exec.preprocess
        ",
    );

    let advice_stack = build_preprocess_advice_stack(1, 0, 1);
    build_test!(&source, &[1], &advice_stack).expect_stack_and_memory(
        &[],
        VICTIM_ADDR,
        &VICTIM_WORD,
    );
}

#[test]
fn fri_preprocess_accepts_full_workspace_bounds() {
    const VICTIM_ADDR: u32 = 0;
    const VICTIM_WORD: [u64; 4] = [91, 92, 93, 94];

    let source = fri_preprocess_source(
        "
        push.[91,92,93,94] push.0 mem_storew_le dropw
        exec.preprocess
        ",
    );

    let advice_stack = build_preprocess_advice_stack(1, 32, 64);
    build_test!(&source, &[1], &advice_stack).expect_stack_and_memory(
        &[],
        VICTIM_ADDR,
        &VICTIM_WORD,
    );
}

fn build_preprocess_advice_stack(
    num_queries: usize,
    num_layers: usize,
    remainder_words: usize,
) -> Vec<u64> {
    let mut stack = vec![];

    stack.push(num_queries as u64);
    for _ in 0..num_queries {
        stack.extend_from_slice(&[0, 0, 0, 0]);
    }

    stack.push(num_layers as u64);
    for _ in 0..(2 * num_layers) {
        stack.extend_from_slice(&[0, 0, 0, 0]);
    }

    stack.push(remainder_words as u64);
    for _ in 0..remainder_words {
        stack.extend_from_slice(&[0, 0, 0, 0]);
    }

    stack
}
