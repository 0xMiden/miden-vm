//! Unit tests for the batch `generate_list_indices` procedure.
//!
//! Verifies that the batch implementation produces identical query indices to a reference
//! implementation that calls `sample_bits` in a loop. Both programs start from the same
//! sponge state and parameters, and we compare the resulting query words stored in memory.

use miden_core::Felt;
use miden_processor::ContextId;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// Memory layout constants (must match constants.masm).
const R1_PTR: u32 = 3223322672;
const R2_PTR: u32 = 3223322676;
const C_PTR: u32 = 3223322668;
const NUM_QUERIES_PTR: u32 = 3223322628;
const LDE_DOMAIN_LOG_SIZE_PTR: u32 = 3223322625;
const FRI_QUERIES_ADDRESS_PTR: u32 = 3223322633;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3223322756;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3223322757;

// Fixed query storage address.
const QUERY_PTR: u32 = 100_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the MASM preamble that initializes the sponge state and verifier parameters.
///
/// `sponge` is 12 field-element values `[r1_0..r1_3, r2_0..r2_3, c_0..c_3]`.
fn setup_masm(sponge: &[u64; 12], output_len: u32, num_queries: u32, depth: u32) -> String {
    format!(
        r#"
    # Store R1 (rate word 1)
    push.{r1_3} push.{r1_2} push.{r1_1} push.{r1_0}
    push.{R1_PTR} mem_storew_le dropw

    # Store R2 (rate word 2)
    push.{r2_3} push.{r2_2} push.{r2_1} push.{r2_0}
    push.{R2_PTR} mem_storew_le dropw

    # Store C (capacity)
    push.{c_3} push.{c_2} push.{c_1} push.{c_0}
    push.{C_PTR} mem_storew_le dropw

    # Random coin buffer state
    push.0 push.{RANDOM_COIN_INPUT_LEN_PTR} mem_store
    push.{output_len} push.{RANDOM_COIN_OUTPUT_LEN_PTR} mem_store

    # Verifier parameters
    push.{num_queries} push.{NUM_QUERIES_PTR} mem_store
    push.{depth} push.{LDE_DOMAIN_LOG_SIZE_PTR} mem_store
    push.{QUERY_PTR} push.{FRI_QUERIES_ADDRESS_PTR} mem_store
    "#,
        r1_0 = sponge[0],
        r1_1 = sponge[1],
        r1_2 = sponge[2],
        r1_3 = sponge[3],
        r2_0 = sponge[4],
        r2_1 = sponge[5],
        r2_2 = sponge[6],
        r2_3 = sponge[7],
        c_0 = sponge[8],
        c_1 = sponge[9],
        c_2 = sponge[10],
        c_3 = sponge[11],
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
    use miden::core::stark::utils
    use miden::core::stark::constants
    use miden::core::crypto::hashes::poseidon2

    #! Sample a felt, permuting first if the output buffer is empty.
    proc sample_felt_safe
        push.{RANDOM_COIN_OUTPUT_LEN_PTR} mem_load
        push.0 eq
        if.true
            exec.random_coin::load_random_coin_state
            exec.poseidon2::permute
            exec.random_coin::store_random_coin_state
            push.8 push.{RANDOM_COIN_OUTPUT_LEN_PTR} mem_store
        end
        exec.random_coin::sample_felt
    end

    #! sample_bits using the safe wrapper.
    proc sample_bits_safe
        dup
        pow2
        u32assert u32overflowing_sub.1 assertz
        exec.sample_felt_safe
        u32split
        swap
        drop
        u32and
        swap
        drop
    end

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
            exec.sample_bits_safe
            dup.2 dup.4 dup.2
            exec.utils::bit_reverse_len_parallel
            push.0 movdn.3
            dup.4
            mem_storew_le
            dropw
            add.4
            movup.3 sub.1 movdn.3
            dup.3 push.0 neq
        end
        push.0 push.{RANDOM_COIN_INPUT_LEN_PTR} mem_store
        drop drop drop drop
    end
    "#,
        RANDOM_COIN_OUTPUT_LEN_PTR = RANDOM_COIN_OUTPUT_LEN_PTR,
        RANDOM_COIN_INPUT_LEN_PTR = RANDOM_COIN_INPUT_LEN_PTR,
    )
}

/// Run both batch and reference programs with identical initial state, then compare
/// all generated query words and the final `output_len`.
fn assert_batch_matches_reference(
    sponge: &[u64; 12],
    output_len: u32,
    num_queries: u32,
    depth: u32,
) {
    let setup = setup_masm(sponge, output_len, num_queries, depth);
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

/// Generate a deterministic sponge state from a seed.
fn random_sponge(seed: u64) -> [u64; 12] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    core::array::from_fn(|_| rng.random::<u64>())
}

// ---------------------------------------------------------------------------
// Parametric tests
// ---------------------------------------------------------------------------

/// Test across a range of num_queries values with fixed sponge and depth.
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
    let sponge = random_sponge(42);
    assert_batch_matches_reference(&sponge, 7, num_queries, 17);
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
    let sponge = random_sponge(99);
    assert_batch_matches_reference(&sponge, 7, 27, depth);
}

/// Test different initial output_len values.
/// After PoW the typical value is 7, but we test the range 1..=8 to ensure
/// the permute-on-exhaustion logic is correct at every boundary.
#[rstest]
#[case::output_len_1(1)]
#[case::output_len_2(2)]
#[case::output_len_4(4)]
#[case::output_len_7(7)]
#[case::output_len_8(8)]
fn batch_vs_reference_output_len(#[case] output_len: u32) {
    let sponge = random_sponge(77);
    assert_batch_matches_reference(&sponge, output_len, 27, 17);
}

/// Test with several different random sponge states to exercise varied rate element values.
#[rstest]
#[case::seed_0(0)]
#[case::seed_1(1)]
#[case::seed_12345(12345)]
#[case::seed_999999(999999)]
fn batch_vs_reference_random_sponge(#[case] seed: u64) {
    let sponge = random_sponge(seed);
    assert_batch_matches_reference(&sponge, 7, 27, 17);
}
