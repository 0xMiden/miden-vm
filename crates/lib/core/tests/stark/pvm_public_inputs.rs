//! Behavioral oracles for the PVM statement and shape transcript hook.

use miden_core::Felt;
use miden_crypto::{
    hash::poseidon2::Poseidon2Permutation256,
    stark::challenger::{CanObserve, DuplexChallenger, FieldChallenger},
};

use crate::helpers::read_memory_felt;

const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3_223_322_638;
const C_PTR: u32 = 3_223_322_668;
const R1_PTR: u32 = 3_223_322_672;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3_223_322_759;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3_223_322_760;
const PVM_PUBLIC_INPUTS_PTR: u32 = 3_225_426_416;
const PVM_PREPROCESSED_COM_PTR: u32 = 3_225_444_208;

const PREPROCESSED_COMMITMENT: [u64; 4] = [
    7_881_474_831_680_931_516,
    14_394_696_689_869_899_287,
    1_264_609_894_509_183_924,
    18_313_229_530_128_768_945,
];
const ROOT: [u64; 4] = [101, 102, 103, 104];
const HEIGHTS: [u64; 10] = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const MAIN_COMMITMENT: [u64; 4] = [201, 202, 203, 204];

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
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::public_inputs

        begin
            {setup}

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
    )
}

#[test]
fn pvm_public_input_hook_matches_the_rust_challenger() {
    let (output, _) = build_test!(&transcript_source(), &[])
        .execute_for_output()
        .expect("PVM public-input hook must execute");

    let mut challenger =
        DuplexChallenger::<Felt, Poseidon2Permutation256, 12, 8>::new(Poseidon2Permutation256);
    challenger.observe_slice(&PREPROCESSED_COMMITMENT.map(Felt::new_unchecked));
    challenger.observe(Felt::from_u8(4));
    challenger.observe_slice(&ROOT.map(Felt::new_unchecked));
    challenger.observe(Felt::ZERO); // max_aux_inputs
    challenger.observe(Felt::ZERO); // aux_inputs.len()
    challenger.observe(Felt::from_u8(10));
    challenger.observe_slice(&HEIGHTS.map(Felt::new_unchecked));
    challenger.observe_slice(&MAIN_COMMITMENT.map(Felt::new_unchecked));
    let expected_sample: Felt = challenger.sample_algebra_element();

    for (i, expected) in challenger.sponge_state[..8].iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, R1_PTR + i as u32),
            *expected,
            "rate state differs at index {i}"
        );
    }
    for (i, expected) in challenger.sponge_state[8..].iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, C_PTR + i as u32),
            *expected,
            "capacity state differs at index {i}"
        );
    }
    assert_eq!(output.stack.get_element(0), Some(expected_sample));
    assert_eq!(read_memory_felt(&output, RANDOM_COIN_INPUT_LEN_PTR), Felt::ZERO);
    assert_eq!(read_memory_felt(&output, RANDOM_COIN_OUTPUT_LEN_PTR), Felt::from_u8(7));

    assert_eq!(
        read_memory_felt(&output, PUBLIC_INPUTS_ADDRESS_PTR),
        Felt::from_u32(PVM_PUBLIC_INPUTS_PTR)
    );
    for (i, expected) in ROOT.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, PVM_PUBLIC_INPUTS_PTR + 2 * i as u32),
            Felt::new_unchecked(expected),
            "public root limb {i} mismatch"
        );
        assert_eq!(
            read_memory_felt(&output, PVM_PUBLIC_INPUTS_PTR + 2 * i as u32 + 1),
            Felt::ZERO,
            "public root extension coordinate {i} was not zeroed"
        );
    }
    for (i, expected) in PREPROCESSED_COMMITMENT.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, PVM_PREPROCESSED_COM_PTR + i as u32),
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
