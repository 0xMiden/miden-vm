//! Compares batched query generation with scalar sampling, including the resulting challenger
//! state.

use miden_core::Felt;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use super::random_coin::read_state;
use crate::helpers::{masm_store_felts, read_memory_felt, stark_constant};

const QUERY_PTR: u32 = 100_000;
const GUARD: Felt = Felt::new_unchecked(0xcafe);

/// Initializes the CV, cached output, and verifier parameters. Query cells start nonzero so an
/// omitted write cannot match the reference's zero field by accident.
fn setup_masm(state: &[Felt; 8], output_len: u32, num_queries: u32, depth: u32) -> String {
    format!(
        "
        {cv}
        {output}
        exec.random_coin::eidos_clear_buffer
        push.{output_len} mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR
        push.1 mem_store.RANDOM_COIN_COUNTER_PTR
        push.{num_queries} mem_store.NUM_QUERIES_PTR
        push.{depth} mem_store.LOG_LDE_DOMAIN_SIZE_PTR
        push.{QUERY_PTR} mem_store.FRI_QUERIES_ADDRESS_PTR
        {queries}
        ",
        cv = masm_store_felts(&state[..4], stark_constant("RANDOM_COIN_CV_PTR")),
        output = masm_store_felts(&state[4..], stark_constant("RANDOM_COIN_OUTPUT_WORD_PTR")),
        queries = masm_store_felts(&vec![GUARD; 4 * num_queries as usize + 2], QUERY_PTR - 1),
    )
}

fn assert_batch_matches_reference(seed: u64, output_len: u32, num_queries: u32, depth: u32) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let state = core::array::from_fn(|_| Felt::new_unchecked(rng.random::<u64>()));
    let setup = setup_masm(&state, output_len, num_queries, depth);
    // sample_bits accepts at most 31 bits; depth 32 uses the low u32 of a sampled felt.
    let sample = if depth == 32 {
        "exec.random_coin::sample_felt u32split swap drop".to_string()
    } else {
        format!("push.{depth} exec.random_coin::sample_bits")
    };
    // The reference writes [index, depth, index, 0] with scalar stores, independently of the
    // batch procedure's stack rearrangement and word stores.
    let reference = (0..num_queries)
        .map(|i| {
            let base = QUERY_PTR + 4 * i;
            format!(
                "{sample} dup mem_store.{base}
                push.{depth} mem_store.{}
                mem_store.{} push.0 mem_store.{}\n",
                base + 1,
                base + 2,
                base + 3,
            )
        })
        .collect::<String>();
    let caller: [u64; 16] = core::array::from_fn(|i| 501 + i as u64);
    let outputs = ["exec.random_coin::generate_list_indices", &reference].map(|body| {
        let source = format!(
            "
            use miden::core::stark::random_coin
            use {{RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR, NUM_QUERIES_PTR,
                  LOG_LDE_DOMAIN_SIZE_PTR, FRI_QUERIES_ADDRESS_PTR}}
                from miden::core::stark::constants
            begin {setup} {body} end
            "
        );
        let (output, _) = build_test!(&source, &caller).execute_for_output().unwrap();
        assert_eq!(output.stack.get_num_elements(16), caller.map(Felt::new_unchecked));
        for address in [QUERY_PTR - 1, QUERY_PTR + 4 * num_queries] {
            assert_eq!(read_memory_felt(&output, address), GUARD, "guard at {address}");
        }
        output
    });
    for address in QUERY_PTR..QUERY_PTR + 4 * num_queries {
        assert_eq!(
            read_memory_felt(&outputs[0], address),
            read_memory_felt(&outputs[1], address),
            "query field at {address}: seed={seed}, queries={num_queries}, depth={depth}, \
             output_len={output_len}"
        );
    }
    assert_eq!(read_state(&outputs[0]), read_state(&outputs[1]), "challenger state");
}

/// Empty and small batches, cache refill boundaries, and repeated refills.
#[rstest]
fn batch_vs_reference_num_queries(#[values(0, 1, 2, 3, 4, 7, 8, 9, 15, 27, 40)] num_queries: u32) {
    assert_batch_matches_reference(42, 3, num_queries, 17);
}

/// Depth 32 requires an all-ones u32 mask.
#[rstest]
fn batch_vs_reference_depth(#[values(10, 13, 17, 20, 24, 32)] depth: u32) {
    assert_batch_matches_reference(99, 3, 27, depth);
}

/// Every valid output-cache occupancy, including an empty cache refill.
#[rstest]
fn batch_vs_reference_output_len(#[values(0, 1, 2, 3, 4)] output_len: u32) {
    assert_batch_matches_reference(77, output_len, 27, 17);
}

#[rstest]
fn batch_vs_reference_random_challenger_state(#[values(0, 1, 12345, 999999)] seed: u64) {
    assert_batch_matches_reference(seed, 3, 27, 17);
}
