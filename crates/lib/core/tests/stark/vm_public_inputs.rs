//! VM statement staging, boundary correction, and transcript parity with Rust.

use std::array;

use miden_air::vm::{MIDEN_AIR_COUNT, MidenMultiAir, config};
use miden_core::{
    Felt, WORD_SIZE, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    program::{KernelDescriptor, NUM_CLAIM_ELEMENTS},
};
use miden_stark::{Preprocessed, StarkConfig, air::Statement};
use miden_vm_stark::setup::config::eidos_config;
use p3_challenger::{CanObserve, FieldChallenger};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use super::{AND8_LOOKUP_LOG_HEIGHT, COPY_ADVICE_TO_MEM, vm_layout_const};
use crate::helpers::{read_memory_felt, read_memory_word, stark_constant};

fn and8_preprocessed_commitment() -> [Felt; WORD_SIZE] {
    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![(0, vec![Felt::ZERO; miden_air::vm::NUM_PUBLIC_VALUES])],
        vec![],
    )
    .expect("zero public inputs satisfy the Miden statement shape");
    let commitment: [u64; WORD_SIZE] = Preprocessed::build(&statement, &config)
        .expect("the Miden relation declares the AND8 preprocessed table")
        .commitment()
        .into();
    commitment.map(Felt::new_unchecked)
}

/// Step-I transcript parity: the MASM Fiat-Shamir schedule (relation digest + PCS params via
/// `init_seed`, preprocessed commitment, `[CLAIM_HASH | D]`, AIR shape as five single felts,
/// main-trace commitment) squeezes the same word as the Rust Eidos challenger fed the identical
/// observation stream.
#[test]
fn public_input_transcript_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let log_heights = [10_u64, 11, 12];
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // The transcript binds the claim only through its commitment; the preimage merely has to be
    // staged for `stage_boundary_inputs`/`load_public_inputs` to read.
    let claim: [u64; NUM_CLAIM_ELEMENTS] = array::from_fn(|_| rng.next_u32() as u64);
    let claim_hash: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let deferred_root: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let main_trace_commitment: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);

    let mut advice_stack = log_heights.to_vec();
    advice_stack.extend_from_slice(&claim);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&main_trace_commitment);

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, MAIN_TRACE_COM_PTR, NUM_QUERIES_PTR,
            QUERY_POW_BITS_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            exec.vm::load_air_context

            # Stage the claim region and commitment the way `vm::verify_proof` leaves them.
            push.{NUM_CLAIM_ELEMENTS} exec.layout::claim_ptr exec.copy_advice_to_mem
            push.{ch3}.{ch2}.{ch1}.{ch0}
            exec.layout::claim_commitment_ptr mem_storew_le dropw
            exec.public_inputs::stage_boundary_inputs

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            # Main-trace commitment, then squeeze (the squeeze flushes the buffered stream).
            padw adv_loadw
            mem_storew_le.MAIN_TRACE_COM_PTR
            exec.random_coin::observe_word
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
        ch0 = claim_hash[0],
        ch1 = claim_hash[1],
        ch2 = claim_hash[2],
        ch3 = claim_hash[3],
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    // Rust mirror over the identical observation stream.
    let config = eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    miden_stark::config::observe_protocol_params(config.pcs(), &mut challenger);
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    for &element in claim_hash.iter().chain(deferred_root.iter()) {
        challenger.observe(Felt::new_unchecked(element));
    }
    challenger.observe(Felt::new_unchecked(MIDEN_AIR_COUNT as u64));
    for log_height in
        [log_heights[0], log_heights[1], log_heights[2], AND8_LOOKUP_LOG_HEIGHT as u64]
    {
        challenger.observe(Felt::new_unchecked(log_height));
    }
    for &element in &main_trace_commitment {
        challenger.observe(Felt::new_unchecked(element));
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(read_memory_word(&output, SQUEEZED_WORD_PTR), expected_word);

    // The squeeze left neither buffered input nor cached output behind.
    assert_eq!(
        read_memory_felt(&output, stark_constant("RANDOM_COIN_INPUT_LENGTH_PTR")),
        Felt::ZERO
    );
    assert_eq!(
        read_memory_felt(&output, stark_constant("RANDOM_COIN_OUTPUT_LENGTH_PTR")),
        Felt::ZERO
    );
}

#[test]
fn eidos_init_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, NUM_QUERIES_PTR, QUERY_POW_BITS_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            exec.vm::load_air_context
            exec.random_coin::init_seed
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
    );

    let shape = [10_u64, 11, 12];
    let test = build_test!(source.as_str(), &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    miden_stark::config::observe_protocol_params(config.pcs(), &mut challenger);
    // `init_seed` also stages the trusted preprocessed-trace commitment onto the buffered stream.
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(read_memory_word(&output, SQUEEZED_WORD_PTR), expected_word);
}

#[test]
fn eidos_relation_digest_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    // The pushed word is `Eidos::transcript_init_cv(STARK_TRANSCRIPT)`, matching the
    // `EIDOS_TRANSCRIPT_INIT_CV_*` constants in `stark/random_coin.masm`.
    let source = "
        use miden::core::sys::vm
        use {RELATION_DIGEST_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            exec.vm::load_air_context
            push.6620516959492505600.11170449401267093504.11912009168875159552.13503953893964383489
            padw mem_loadw_le.RELATION_DIGEST_PTR
            exec.random_coin::eidos_init_challenger
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let shape = [10_u64, 11, 12];
    let test = build_test!(source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(read_memory_word(&output, SQUEEZED_WORD_PTR), expected_word);
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
#[case(KernelDescriptor::MAX_NUM_PROCEDURES)]
fn boundary_inputs_and_outer_logup_boundary(#[case] num_kernel_procedures: usize) {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let stack_inputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let stack_outputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let deferred_root: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let kernel_digest_felts: Vec<u64> =
        (0..num_kernel_procedures * WORD_SIZE).map(|_| rng.next_u64()).collect();
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    let initial_stack = vec![num_kernel_procedures as u64];

    // Advice order: kernel digests (4N), claim encoding (P, K, I, O), deferred root, then the
    // auxiliary randomness used by `compute_outer_logup_correction`.
    let digest_felts: Vec<Felt> =
        kernel_digest_felts.iter().map(|&v| Felt::new_unchecked(v)).collect();
    let expected_kernel_h = miden_air_definitions::vm::hash_kernel_digests(&digest_felts);
    let mut claim_elements = [Felt::ZERO; NUM_CLAIM_ELEMENTS];
    claim_elements[..WORD_SIZE].copy_from_slice(&program_digest.map(Felt::new_unchecked));
    claim_elements[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(&expected_kernel_h);
    claim_elements[2 * WORD_SIZE..6 * WORD_SIZE]
        .copy_from_slice(&stack_inputs.map(Felt::new_unchecked));
    claim_elements[6 * WORD_SIZE..].copy_from_slice(&stack_outputs.map(Felt::new_unchecked));
    let [claim_c0, claim_c1, claim_c2, claim_c3] =
        miden_core::program::claim_commitment(&claim_elements)
            .into_elements()
            .map(|felt| felt.as_canonical_u64());

    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&kernel_digest_felts);
    advice_stack.extend_from_slice(&program_digest);
    advice_stack.extend(expected_kernel_h.iter().map(Felt::as_canonical_u64));
    advice_stack.extend_from_slice(&stack_inputs);
    advice_stack.extend_from_slice(&stack_outputs);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    // Inject the auxiliary challenges where `generate_aux_randomness` stores them, so the MASM
    // boundary correction and the Rust calculation below use the same challenges.
    let source = format!(
        "
        use miden::core::stark::random_coin
        use {{LOG_TRACE_LENGTH_PTR, RELATION_DIGEST_PTR}} from miden::core::stark::constants
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            # Initial stack: [num_kernel_procedures].

            # Copy kernel digests (4·num_kernel_procedures felts) from advice into the witness
            # region. Build [dst=KERNEL_WITNESS_PTR, count=4N].
            dup mul.4 exec.layout::kernel_witness_ptr
            exec.copy_advice_to_mem

            # Copy the full claim encoding P | K | I | O into verifier-owned memory.
            push.{NUM_CLAIM_ELEMENTS} exec.layout::claim_ptr
            exec.copy_advice_to_mem

            exec.layout::num_kernel_procedures_ptr mem_store
            exec.public_inputs::stage_boundary_inputs

            push.10 exec.layout::set_core_trace_length_log
            push.10 exec.layout::set_chiplets_trace_length_log
            push.10 exec.layout::set_eidos_compression_trace_length_log
            exec.layout::init_and8_lookup_trace_length_log
            push.16 mem_store.LOG_TRACE_LENGTH_PTR
            push.4.3.2.1 mem_storew_le.RELATION_DIGEST_PTR dropw
            push.{claim_c3}.{claim_c2}.{claim_c1}.{claim_c0}
            exec.layout::claim_commitment_ptr mem_storew_le dropw

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            padw adv_loadw push.{aux_rand_elem_ptr} mem_storew_le dropw
            exec.public_inputs::compute_outer_logup_correction
        end
        ",
        aux_rand_elem_ptr = stark_constant("AUX_RAND_ELEM_PTR"),
    );

    let test = build_test!(source.as_str(), &initial_stack, &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let read_elem = |addr| read_memory_felt(&output, addr).as_canonical_u64();
    let boundary_inputs_ptr = vm_layout_const("BOUNDARY_INPUTS_PTR");
    let c_total_ptr = vm_layout_const("C_TOTAL_PTR");
    let pi_ptr = read_elem(stark_constant("PUBLIC_INPUTS_ADDRESS_PTR")) as u32;

    // The boundary-inputs block contains the program digest and deferred root.
    for (i, &v) in program_digest.iter().chain(deferred_root.iter()).enumerate() {
        assert_eq!(
            read_elem(boundary_inputs_ptr + i as u32),
            v,
            "boundary-inputs window felt {i} mismatch"
        );
    }
    // Stack inputs and outputs are embedded as extension-field elements [value, 0].
    for (i, &v) in stack_inputs.iter().chain(stack_outputs.iter()).enumerate() {
        assert_eq!(read_elem(pi_ptr + 2 * i as u32), v, "FLPI slot {i} value mismatch");
        assert_eq!(read_elem(pi_ptr + 2 * i as u32 + 1), 0, "FLPI slot {i} high coord");
    }

    // Outer-LogUp boundary correction, matching `MidenMultiAir::eval_external`:
    //
    //     c_total = Σ_i 1 / ((α + γ) + msg(kernel_digest_i))
    //             + 1 / ((α + 2γ) + msg(program_digest))
    //             + 1 / (α + 3γ)
    //             − 1 / ((α + 3γ) + msg(deferred_root))
    //
    // with γ = β^16 and msg(w) = Σ w_i·β^i.
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let msg = |felts: &[u64]| -> QuadFelt {
        felts
            .iter()
            .rev()
            .fold(QuadFelt::ZERO, |acc, m| acc * beta + QuadFelt::from(Felt::new_unchecked(*m)))
    };

    let kernel_corr = kernel_digest_felts
        .as_chunks::<WORD_SIZE>()
        .0
        .iter()
        .map(|digest| alpha + gamma + msg(digest))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        });
    let d_bh = alpha + gamma.double() + msg(&program_digest);
    let prefix_lp = alpha + gamma * QuadFelt::from_u8(3);
    let d_lpf = prefix_lp + msg(&deferred_root);
    let expected_c_total = kernel_corr
        + d_bh.try_inverse().expect("zero block-hash denominator")
        + prefix_lp.try_inverse().expect("zero log-deferred init denominator")
        - d_lpf.try_inverse().expect("zero log-deferred final denominator");
    let expected: &[Felt] = expected_c_total.as_basis_coefficients_slice();

    assert_eq!(
        read_elem(c_total_ptr),
        expected[0].as_canonical_u64(),
        "c_total coord 0 mismatch (nk={num_kernel_procedures})"
    );
    assert_eq!(
        read_elem(c_total_ptr + 1),
        expected[1].as_canonical_u64(),
        "c_total coord 1 mismatch (nk={num_kernel_procedures})"
    );
}
