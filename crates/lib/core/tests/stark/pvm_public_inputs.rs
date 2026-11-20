//! Behavioral oracles for the PVM statement and shape transcript hook.

use miden_air::precompiles::{ChipletAir, ChipletMultiAir};
use miden_core::{Felt, Word, field::QuadFelt};
use miden_stark::{StarkConfig, air::Statement, config::observe_protocol_params, pcs::PcsParams};
use miden_vm_stark::setup::config::eidos_config;
use p3_challenger::{CanObserve, FieldChallenger};

use super::pvm_layout_const;
use crate::helpers::{masm_push_word, masm_store_felts, read_memory_felt, stark_constant};

const ROOT: [u64; 4] = [101, 102, 103, 104];
const HEIGHTS: [u64; 12] = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
const MAIN_COMMITMENT: [u64; 4] = [201, 202, 203, 204];

fn pvm_masm_const(name: &str) -> u64 {
    let source = include_str!("../../asm/sys/pvm/parameters.masm");
    let prefix = format!("pub const {name} = ");
    source
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix)?.parse().ok())
        .unwrap_or_else(|| panic!("missing PVM MASM constant {name}"))
}

fn pvm_word(prefix: &str) -> [u64; 4] {
    core::array::from_fn(|index| pvm_masm_const(&format!("{prefix}_{index}")))
}

fn precompile_pcs_params() -> PcsParams {
    PcsParams::new(3, 2, 7, 4, 12, 27, 17).expect("valid PVM PCS parameters")
}

fn stage_statement_and_shape() -> String {
    let root = masm_push_word(&Word::new(ROOT.map(Felt::new_unchecked)));
    let heights = masm_store_felts(
        &HEIGHTS.map(Felt::new_unchecked),
        stark_constant("LOG_AIR_TRACE_LENGTHS_PTR"),
    );
    format!(
        r#"
        # Both words must be overwritten, including every high extension coordinate.
        push.99.98.97.96
        push.PUBLIC_INPUTS_PTR mem_storew_le
        push.PUBLIC_INPUTS_PTR add.4 mem_storew_le dropw

        {root}
        exec.public_inputs::stage_public_root
        {heights}
        "#,
    )
}

fn transcript_source() -> String {
    let setup = stage_statement_and_shape();
    let main = masm_push_word(&Word::new(MAIN_COMMITMENT.map(Felt::new_unchecked)));
    let relation = masm_push_word(&Word::new(pvm_word("RELATION_DIGEST").map(Felt::new_unchecked)));
    let preprocessed =
        masm_push_word(&Word::new(pvm_word("PREPROCESSED_COMMITMENT").map(Felt::new_unchecked)));
    let params = precompile_pcs_params();
    format!(
        r#"
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR,
            LOG_TRACE_LENGTH_PTR, NUM_QUERIES_PTR, PREPROCESSED_TRACE_COM_PTR, QUERY_POW_BITS_PTR,
            RELATION_DIGEST_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin
        use {{PUBLIC_INPUTS_PTR}} from miden::core::sys::pvm::layout
        use miden::core::sys::pvm::public_inputs

        begin
            {setup}

            {relation}
            mem_storew_le.RELATION_DIGEST_PTR dropw
            {preprocessed}
            mem_storew_le.PREPROCESSED_TRACE_COM_PTR dropw

            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            push.15 mem_store.LOG_TRACE_LENGTH_PTR
            exec.random_coin::init_seed

            exec.public_inputs::process_public_inputs

            {main}
            exec.random_coin::observe_word_and_flush_buffer
            exec.random_coin::sample_felt
            swap drop
        end
        "#,
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
    )
}

#[test]
fn pvm_public_input_hook_matches_the_rust_challenger() {
    let (output, _) = build_test!(&transcript_source(), &[])
        .execute_for_output()
        .expect("PVM public-input hook must execute");

    let params = precompile_pcs_params();
    let relation_digest = pvm_word("RELATION_DIGEST");
    let preprocessed_commitment = pvm_word("PREPROCESSED_COMMITMENT");
    let public_inputs_ptr = pvm_layout_const("PUBLIC_INPUTS_PTR");
    let preprocessed_com_ptr = stark_constant("PREPROCESSED_TRACE_COM_PTR");
    let config = eidos_config(params, relation_digest.map(Felt::new_unchecked));
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    challenger.observe_slice(&preprocessed_commitment.map(Felt::new_unchecked));
    let statement = Statement::<Felt, QuadFelt, _>::new(
        ChipletMultiAir::new(),
        vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, ROOT.map(Felt::new_unchecked).to_vec())],
        vec![],
    )
    .expect("PVM statement must match the native relation");
    assert_eq!(statement.airs().len(), HEIGHTS.len());
    statement.observe(&mut challenger, &HEIGHTS.map(|height| height as u8));
    challenger.observe(Felt::from_u32(statement.airs().len() as u32));
    challenger.observe_slice(&HEIGHTS.map(Felt::new_unchecked));
    challenger.observe_slice(&MAIN_COMMITMENT.map(Felt::new_unchecked));
    let mut cv_oracle = challenger.clone();
    let expected_cv: [Felt; 4] = core::array::from_fn(|_| cv_oracle.sample_algebra_element());
    let expected_sample: Felt = challenger.sample_algebra_element();

    for (i, expected) in expected_cv.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, stark_constant("RANDOM_COIN_CV_PTR") + i as u32),
            *expected,
            "Eidos transcript CV differs at index {i}"
        );
    }
    assert_eq!(output.stack.get_element(0), Some(expected_sample));
    assert_eq!(
        read_memory_felt(&output, stark_constant("RANDOM_COIN_INPUT_LENGTH_PTR")),
        Felt::ZERO
    );
    assert_eq!(
        read_memory_felt(&output, stark_constant("RANDOM_COIN_OUTPUT_LENGTH_PTR")),
        Felt::from_u8(3)
    );

    for (i, expected) in ROOT.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, public_inputs_ptr + 2 * i as u32),
            Felt::new_unchecked(expected),
            "public root limb {i} mismatch"
        );
        assert_eq!(
            read_memory_felt(&output, public_inputs_ptr + 2 * i as u32 + 1),
            Felt::ZERO,
            "public root extension coordinate {i} was not zeroed"
        );
    }
    for (i, expected) in preprocessed_commitment.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, preprocessed_com_ptr + i as u32),
            Felt::new_unchecked(expected),
            "stored preprocessed commitment limb {i} mismatch"
        );
    }
}

#[test]
fn pvm_public_input_hook_rejects_a_nonempty_input_buffer() {
    let source = r#"
        use {RANDOM_COIN_INPUT_LENGTH_PTR} from miden::core::stark::constants
        use miden::core::sys::pvm::public_inputs

        begin
            push.1 mem_store.RANDOM_COIN_INPUT_LENGTH_PTR
            exec.public_inputs::process_public_inputs
        end
    "#;
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}
