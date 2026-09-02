//! Behavioral oracles for the PVM statement and shape transcript hook.

use miden_air::config::{eidos_config, observe_protocol_params};
use miden_core::Felt;
use miden_crypto::stark::{
    StarkConfig,
    challenger::{CanObserve, FieldChallenger},
    pcs::PcsParams,
};

use super::pvm_layout_const;
use crate::helpers::read_memory_felt;

const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3_223_322_638;
const RANDOM_COIN_CV_PTR: u32 = 3_223_322_668;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3_223_322_767;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3_223_322_768;
const ROOT: [u64; 4] = [101, 102, 103, 104];
const HEIGHTS: [u64; 10] = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const MAIN_COMMITMENT: [u64; 4] = [201, 202, 203, 204];

fn pvm_masm_const(name: &str) -> u64 {
    let source = include_str!("../../asm/sys/pvm/mod.masm");
    let prefix = format!("const {name} = ");
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
    let root = ROOT;
    let heights = HEIGHTS;
    format!(
        r#"
        push.{root3}.{root2}.{root1}.{root0}
        exec.public_inputs::stage_public_root

        push.{h0} exec.constants::air_trace_length_logs_ptr mem_store
        push.{h1} exec.constants::air_trace_length_logs_ptr add.1 mem_store
        push.{h2} exec.constants::air_trace_length_logs_ptr add.2 mem_store
        push.{h3} exec.constants::air_trace_length_logs_ptr add.3 mem_store
        push.{h4} exec.constants::air_trace_length_logs_ptr add.4 mem_store
        push.{h5} exec.constants::air_trace_length_logs_ptr add.5 mem_store
        push.{h6} exec.constants::air_trace_length_logs_ptr add.6 mem_store
        push.{h7} exec.constants::air_trace_length_logs_ptr add.7 mem_store
        push.{h8} exec.constants::air_trace_length_logs_ptr add.8 mem_store
        push.{h9} exec.constants::air_trace_length_logs_ptr add.9 mem_store
        "#,
        root0 = root[0],
        root1 = root[1],
        root2 = root[2],
        root3 = root[3],
        h0 = heights[0],
        h1 = heights[1],
        h2 = heights[2],
        h3 = heights[3],
        h4 = heights[4],
        h5 = heights[5],
        h6 = heights[6],
        h7 = heights[7],
        h8 = heights[8],
        h9 = heights[9],
    )
}

fn transcript_source() -> String {
    let setup = stage_statement_and_shape();
    let main = MAIN_COMMITMENT;
    let relation = pvm_word("RELATION_DIGEST");
    let preprocessed = pvm_word("PREPROCESSED_COMMITMENT");
    let params = precompile_pcs_params();
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::layout
        use miden::core::sys::pvm::public_inputs

        begin
            {setup}

            push.{relation3}.{relation2}.{relation1}.{relation0}
            exec.constants::relation_digest_ptr mem_storew_le dropw
            push.{preprocessed3}.{preprocessed2}.{preprocessed1}.{preprocessed0}
            dupw exec.constants::preprocessed_trace_com_ptr mem_storew_le dropw
            exec.layout::preprocessed_com_ptr mem_storew_le dropw

            push.{num_queries} exec.constants::set_number_queries
            push.{query_pow_bits} exec.constants::set_query_pow_bits
            push.{deep_pow_bits} exec.constants::set_deep_pow_bits
            push.{folding_pow_bits} exec.constants::set_folding_pow_bits
            push.15 exec.constants::set_trace_length_log
            exec.random_coin::init_seed

            exec.public_inputs::process_public_inputs

            push.{main3}.{main2}.{main1}.{main0}
            exec.random_coin::observe_word_and_flush_buffer
            exec.random_coin::sample_felt
            swap drop
        end
        "#,
        main0 = main[0],
        main1 = main[1],
        main2 = main[2],
        main3 = main[3],
        relation0 = relation[0],
        relation1 = relation[1],
        relation2 = relation[2],
        relation3 = relation[3],
        preprocessed0 = preprocessed[0],
        preprocessed1 = preprocessed[1],
        preprocessed2 = preprocessed[2],
        preprocessed3 = preprocessed[3],
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
    let preprocessed_com_ptr = pvm_layout_const("PREPROCESSED_COM_PTR");
    let config = eidos_config(params, relation_digest.map(Felt::new_unchecked));
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    challenger.observe_slice(&preprocessed_commitment.map(Felt::new_unchecked));
    challenger.observe(Felt::from_u8(4));
    challenger.observe_slice(&ROOT.map(Felt::new_unchecked));
    challenger.observe(Felt::ZERO); // max_aux_inputs
    challenger.observe(Felt::ZERO); // aux_inputs.len()
    challenger.observe(Felt::from_u8(10));
    challenger.observe_slice(&HEIGHTS.map(Felt::new_unchecked));
    challenger.observe_slice(&MAIN_COMMITMENT.map(Felt::new_unchecked));
    let mut cv_oracle = challenger.clone();
    let expected_cv: [Felt; 4] = core::array::from_fn(|_| cv_oracle.sample_algebra_element());
    let expected_sample: Felt = challenger.sample_algebra_element();

    for (i, expected) in expected_cv.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, RANDOM_COIN_CV_PTR + i as u32),
            *expected,
            "Eidos transcript CV differs at index {i}"
        );
    }
    assert_eq!(output.stack.get_element(0), Some(expected_sample));
    assert_eq!(read_memory_felt(&output, RANDOM_COIN_INPUT_LEN_PTR), Felt::ZERO);
    assert_eq!(read_memory_felt(&output, RANDOM_COIN_OUTPUT_LEN_PTR), Felt::from_u8(3));

    assert_eq!(
        read_memory_felt(&output, PUBLIC_INPUTS_ADDRESS_PTR),
        Felt::from_u32(public_inputs_ptr)
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
        use miden::core::stark::constants
        use miden::core::sys::pvm::public_inputs

        begin
            push.1 exec.constants::random_coin_input_len_ptr mem_store
            exec.public_inputs::process_public_inputs
        end
    "#;
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}
