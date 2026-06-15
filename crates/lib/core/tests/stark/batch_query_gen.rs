//! Unit tests for the batch `generate_list_indices` procedure.
//!
//! Verifies that the batch implementation produces identical query indices to a reference
//! implementation that calls `sample_bits` in a loop. Both programs start from the same
//! Eidos challenger state and parameters, and we compare the resulting query words stored in
//! memory.

use miden_core::Felt;
use miden_processor::ContextId;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// Memory layout constants (must match constants.masm).
const RANDOM_COIN_CV_PTR: u32 = 3223322672;
const RANDOM_COIN_OUTPUT_WORD_PTR: u32 = 3223322676;
const NUM_QUERIES_PTR: u32 = 3223322628;
const LDE_DOMAIN_LOG_SIZE_PTR: u32 = 3223322625;
const FRI_QUERIES_ADDRESS_PTR: u32 = 3223322633;
const RANDOM_COIN_INPUT_BUF_PTR: u32 = 3223322752;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3223322760;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3223322761;
const RANDOM_COIN_COUNTER_PTR: u32 = 3223322762;

// Fixed query storage address.
const QUERY_PTR: u32 = 100_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the MASM preamble that initializes the Eidos state and verifier parameters.
///
/// `state` is `[output_word[0..4], cv[0..4]]`.
fn setup_masm(state: &[u64; 8], output_len: u32, num_queries: u32, depth: u32) -> String {
    format!(
        r#"
    # Store the currently buffered output word.
    push.{out_3}.{out_2}.{out_1}.{out_0}
    push.{RANDOM_COIN_OUTPUT_WORD_PTR} mem_storew_le dropw

    # Store the Eidos chaining value.
    push.{c_3}.{c_2}.{c_1}.{c_0}
    push.{RANDOM_COIN_CV_PTR} mem_storew_le dropw

    # Random coin buffer state. The tests start in squeezing state with no pending absorb.
    # Internally, counter=1 means the next refill uses counter block 1.
    padw push.{RANDOM_COIN_INPUT_BUF_PTR} mem_storew_le dropw
    padw push.{RANDOM_COIN_INPUT_BUF_PTR_PLUS_4} mem_storew_le dropw
    push.0 push.{RANDOM_COIN_INPUT_LEN_PTR} mem_store
    push.{output_len} push.{RANDOM_COIN_OUTPUT_LEN_PTR} mem_store
    push.1 push.{RANDOM_COIN_COUNTER_PTR} mem_store

    # Verifier parameters
    push.{num_queries} push.{NUM_QUERIES_PTR} mem_store
    push.{depth} push.{LDE_DOMAIN_LOG_SIZE_PTR} mem_store
    push.{QUERY_PTR} push.{FRI_QUERIES_ADDRESS_PTR} mem_store
    "#,
        out_0 = state[0],
        out_1 = state[1],
        out_2 = state[2],
        out_3 = state[3],
        c_0 = state[4],
        c_1 = state[5],
        c_2 = state[6],
        c_3 = state[7],
        RANDOM_COIN_INPUT_BUF_PTR_PLUS_4 = RANDOM_COIN_INPUT_BUF_PTR + 4,
    )
}

/// MASM source that calls the batch `generate_list_indices`.
fn batch_source(setup: &str) -> String {
    format!(
        r#"
    use miden::core::stark::random_coin
    begin
        {setup}
        exec.random_coin::generate_list_indices
    end
    "#,
    )
}

/// MASM source with a reference per-query loop.
fn reference_source(setup: &str) -> String {
    format!(
        r#"
    use miden::core::stark::random_coin
    use miden::core::stark::constants

    begin
        {setup}

        exec.constants::get_number_queries
        exec.constants::get_fri_queries_address
        exec.constants::get_lde_domain_depth
        dup push.32 swap u32wrapping_sub pow2
        movdn.2 swap
        dup.3 push.0 neq
        while.true
            dup.1
            exec.random_coin::sample_bits
            dup.2 swap dup movdn.2
            push.0 movdn.3
            dup.4
            mem_storew_le
            dropw
            add.4
            movup.3 sub.1 movdn.3
            dup.3 push.0 neq
        end
        drop drop drop drop
    end
    "#,
    )
}

/// Run both batch and reference programs with identical initial state, then compare
/// all generated query words and the final `output_len`.
fn assert_batch_matches_reference(state: &[u64; 8], output_len: u32, num_queries: u32, depth: u32) {
    let setup = setup_masm(state, output_len, num_queries, depth);
    let batch_src = batch_source(&setup);
    let ref_src = reference_source(&setup);

    let (batch_out, _) = build_test!(&batch_src, &[]).execute_for_output().unwrap_or_else(|e| {
        panic!("batch failed (nq={num_queries}, d={depth}, ol={output_len}): {e}")
    });
    let (ref_out, _) = build_test!(&ref_src, &[]).execute_for_output().unwrap_or_else(|e| {
        panic!("reference failed (nq={num_queries}, d={depth}, ol={output_len}): {e}")
    });

    // Compare every stored query word.
    for i in 0..num_queries {
        let base = QUERY_PTR + i * 4;
        for j in 0..4u32 {
            let addr = base + j;
            let bv = batch_out
                .memory
                .read_element(ContextId::root(), Felt::from_u32(addr))
                .map(|f| f.as_canonical_u64())
                .unwrap_or(0);
            let rv = ref_out
                .memory
                .read_element(ContextId::root(), Felt::from_u32(addr))
                .map(|f| f.as_canonical_u64())
                .unwrap_or(0);
            assert_eq!(
                bv, rv,
                "query {i} offset {j} (addr {addr}): batch={bv} vs ref={rv} \
                 [nq={num_queries}, depth={depth}, output_len={output_len}]"
            );
        }
    }

    // Compare final output_len.
    let b_ol = batch_out
        .memory
        .read_element(ContextId::root(), Felt::from_u32(RANDOM_COIN_OUTPUT_LEN_PTR))
        .map(|f| f.as_canonical_u64())
        .unwrap_or(u64::MAX);
    let r_ol = ref_out
        .memory
        .read_element(ContextId::root(), Felt::from_u32(RANDOM_COIN_OUTPUT_LEN_PTR))
        .map(|f| f.as_canonical_u64())
        .unwrap_or(u64::MAX);
    assert_eq!(
        b_ol, r_ol,
        "output_len mismatch: batch={b_ol} vs ref={r_ol} \
         [nq={num_queries}, depth={depth}, output_len={output_len}]"
    );
}

/// Generate a deterministic Eidos state from a seed.
fn random_eidos_state(seed: u64) -> [u64; 8] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    core::array::from_fn(|_| rng.random::<u64>() % (1u64 << 62))
}

// ---------------------------------------------------------------------------
// Parametric tests
// ---------------------------------------------------------------------------

/// Test across a range of num_queries values with fixed Eidos state and depth.
/// Covers: 1 query, small batches, exact rate boundary (7), one past (8, 9),
/// typical (27), and a larger value (40 = 5 permutations).
#[rstest]
#[case::single_query(1)]
#[case::two_queries(2)]
#[case::three_queries(3)]
#[case::seven_queries_exact_first_batch(7)]
#[case::eight_queries_triggers_permute(8)]
#[case::nine_queries_one_past_permute(9)]
#[case::fifteen_queries_two_batches(15)]
#[case::twentyseven_queries_typical(27)]
#[case::forty_queries_five_permutes(40)]
fn batch_vs_reference_num_queries(#[case] num_queries: u32) {
    let state = random_eidos_state(42);
    assert_batch_matches_reference(&state, 3, num_queries, 17);
}

/// Test across a range of LDE domain depths.
/// depth must be in 1..=31 (since pow2_shift = 2^(32-depth) must fit in u32,
/// and mask = 2^depth - 1 must be valid).
#[rstest]
#[case::depth_10(10)]
#[case::depth_13(13)]
#[case::depth_17(17)]
#[case::depth_20(20)]
#[case::depth_24(24)]
fn batch_vs_reference_depth(#[case] depth: u32) {
    let state = random_eidos_state(99);
    assert_batch_matches_reference(&state, 3, 27, depth);
}

/// Test different initial output_len values.
/// Eidos output words contain four felts; cover empty, partial, and full buffers.
#[rstest]
#[case::output_len_0(0)]
#[case::output_len_1(1)]
#[case::output_len_2(2)]
#[case::output_len_3(3)]
#[case::output_len_4(4)]
fn batch_vs_reference_output_len(#[case] output_len: u32) {
    let state = random_eidos_state(77);
    assert_batch_matches_reference(&state, output_len, 27, 17);
}

/// Test with several different random Eidos states.
#[rstest]
#[case::seed_0(0)]
#[case::seed_1(1)]
#[case::seed_12345(12345)]
#[case::seed_999999(999999)]
fn batch_vs_reference_random_eidos_state(#[case] seed: u64) {
    let state = random_eidos_state(seed);
    assert_batch_matches_reference(&state, 3, 27, 17);
}
