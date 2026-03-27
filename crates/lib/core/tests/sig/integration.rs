//! Integration tests for the STARK-based signature verifier.
//! See README.md in this folder for how to run tests and benchmarks.

use miden_core::Felt;
use miden_signature::{QuadExt, internal::transcript::Poseidon2Suite};

use super::{
    SigVerifierData,
    conversions::ef_to_felts,
    fixtures::{
        advice_map_with_sig_proof, advice_map_with_sig_proofs, build_fixture,
        build_fixture_with_message, hash_message,
    },
    instance_seed_goldilocks, test_message,
};

fn build_sig_test(source: &str, data: &SigVerifierData) -> miden_utils_testing::Test {
    build_test!(
        source,
        &data.initial_stack,
        &data.advice_stack,
        data.store.clone(),
        data.advice_map.clone()
    )
}

// ── Tests ──

#[test]
fn sign_and_extract_proof_components() {
    let fixture = build_fixture(b"test-seed-for-recursive-verification", 1001);
    assert_eq!(fixture.proof.witness_z.len(), 8);
    assert_eq!(fixture.proof.deep_coeffs.len(), fixture.config.stark.message_size());
}

#[test]
fn transcript_matches_prover() {
    let fixture = build_fixture(b"transcript-test-seed", 1002);
    // If pack_proof_for_masm succeeded, transcript was replayed correctly
    // witness + quotient Merkle entries + 1 circuit entry
    assert_eq!(fixture.data.advice_map.len(), fixture.config.stark.num_queries * 2 + 1);
}

#[test]
fn masm_query_indices_match_transcript_replay() {
    use miden_processor::ContextId;

    const SIG_QUERIES_PTR: u32 = 3240100232;

    let fixture = build_fixture(b"masm-query-indices-match-replay", 1003);
    let expected = miden_signature::internal::proof::replay_query_indices::<QuadExt, Poseidon2Suite>(
        &fixture.config.stark,
        *fixture.pk.elements(),
        &fixture.proof,
        hash_message(fixture.message),
        instance_seed_goldilocks(),
    );

    let setup_source = "
        use miden::core::sig
        use miden::core::sys
        begin
            exec.sig::verify_signature_setup
            exec.sys::truncate_stack
        end
    ";
    let setup_test = build_sig_test(setup_source, &fixture.data);
    let (setup_output, _host) = setup_test.execute_for_output().expect("setup execution failed");

    let ctx = ContextId::root();
    let mut masm_indices = Vec::with_capacity(fixture.config.stark.num_queries);
    for i in 0..fixture.config.stark.num_queries {
        let addr = SIG_QUERIES_PTR + (i as u32) * 4;
        let idx = setup_output
            .memory
            .read_element(ctx, Felt::from_u32(addr))
            .expect("query index not written")
            .as_canonical_u64() as usize;
        masm_indices.push(idx);
    }

    assert_eq!(
        masm_indices, expected,
        "MASM query memory layout drifted from transcript replay"
    );
}

#[test]
fn masm_verify_signature_phases_0_to_4() {
    let fixture = build_fixture(b"masm-execution-test", 1004);

    // Full end-to-end MASM signature verification (includes all DEEP queries).
    let source = "
        use miden::core::sig
        begin
            exec.sig::verify_signature
        end
    ";

    let test = build_sig_test(source, &fixture.data);

    test.execute().expect("MASM signature verifier failed");
}

#[test]
fn masm_verify_signature_from_map() {
    let fixture = build_fixture(b"masm-map-verification-test", 1005);
    let advice_map = advice_map_with_sig_proof(&fixture.data);

    let source = "
        use miden::core::sig
        begin
            exec.sig::verify_signature_from_map
        end
    ";

    let test = build_test!(
        source,
        &fixture.data.initial_stack,
        &[],
        fixture.data.store.clone(),
        advice_map
    );
    test.execute().expect("MASM verify_signature_from_map failed");
}

#[test]
fn masm_verify_signature_batch_2() {
    let fixture = build_fixture(b"masm-batch-2-test", 1006);

    let mut advice = Vec::with_capacity(fixture.data.advice_stack.len() * 2);
    advice.extend_from_slice(&fixture.data.advice_stack);
    advice.extend_from_slice(&fixture.data.advice_stack);

    let mut stack = Vec::with_capacity(fixture.data.initial_stack.len() * 2);
    stack.extend_from_slice(&fixture.data.initial_stack);
    stack.extend_from_slice(&fixture.data.initial_stack);

    let source = "
        use miden::core::sig::batch
        begin
            exec.batch::verify_2
        end
    ";

    let test = build_test!(
        source,
        &stack,
        &advice,
        fixture.data.store.clone(),
        fixture.data.advice_map.clone()
    );
    test.execute().expect("MASM batch verifier (2 signatures) failed");
}

#[test]
fn masm_verify_signature_batch_2_from_map() {
    let fixture = build_fixture(b"masm-batch-2-map-test", 1007);
    let advice_map = advice_map_with_sig_proof(&fixture.data);

    let mut stack = Vec::with_capacity(fixture.data.initial_stack.len() * 2);
    stack.extend_from_slice(&fixture.data.initial_stack);
    stack.extend_from_slice(&fixture.data.initial_stack);

    let source = "
        use miden::core::sig
        begin
            repeat.2
                exec.sig::verify_signature_from_map
            end
        end
    ";

    let test = build_test!(source, &stack, &[], fixture.data.store.clone(), advice_map);
    test.execute().expect("MASM batch verifier (2 signatures, map) failed");
}

#[test]
fn masm_verify_signature_batch_2_shared_message_distinct_signers() {
    let message = test_message(1008);
    let fixture0 = build_fixture_with_message(b"masm-batch-shared-msg-signer-0", message);
    let fixture1 = build_fixture_with_message(b"masm-batch-shared-msg-signer-1", message);

    let shared_msg0 = &fixture0.data.initial_stack[4..8];
    let shared_msg1 = &fixture1.data.initial_stack[4..8];
    assert_eq!(shared_msg0, shared_msg1, "message felts must match in shared-message mode");

    let mut advice =
        Vec::with_capacity(fixture0.data.advice_stack.len() + fixture1.data.advice_stack.len());
    advice.extend_from_slice(&fixture0.data.advice_stack);
    advice.extend_from_slice(&fixture1.data.advice_stack);

    let mut stack = Vec::with_capacity(12);
    stack.extend_from_slice(shared_msg0);
    stack.extend_from_slice(&fixture0.data.initial_stack[0..4]);
    stack.extend_from_slice(&fixture1.data.initial_stack[0..4]);

    let mut store = fixture0.data.store.clone();
    store.extend(fixture1.data.store.inner_nodes());

    let mut advice_map = fixture0.data.advice_map.clone();
    advice_map.extend(fixture1.data.advice_map.clone());

    let source = "
        use miden::core::sig::batch
        begin
            exec.batch::verify_same_msg_2
        end
    ";

    let test = build_test!(source, &stack, &advice, store, advice_map);
    test.execute()
        .expect("MASM shared-message batch verifier (2 distinct signers) failed");
}

#[test]
fn masm_verify_signature_batch_2_shared_message_distinct_signers_from_map() {
    let message = test_message(1009);
    let fixture0 = build_fixture_with_message(b"masm-batch-shared-msg-map-signer-0", message);
    let fixture1 = build_fixture_with_message(b"masm-batch-shared-msg-map-signer-1", message);

    let shared_msg0 = &fixture0.data.initial_stack[4..8];
    let shared_msg1 = &fixture1.data.initial_stack[4..8];
    assert_eq!(shared_msg0, shared_msg1, "message felts must match in shared-message mode");

    let mut stack = Vec::with_capacity(12);
    stack.extend_from_slice(shared_msg0);
    stack.extend_from_slice(&fixture0.data.initial_stack[0..4]);
    stack.extend_from_slice(&fixture1.data.initial_stack[0..4]);

    let mut store = fixture0.data.store.clone();
    store.extend(fixture1.data.store.inner_nodes());

    let advice_map = advice_map_with_sig_proofs(&[&fixture0.data, &fixture1.data]);

    let source = "
        use miden::core::sig
        use miden::core::sig::constants
        begin
            exec.constants::sig_msg_ptr mem_storew_le
            dropw
            repeat.2
                padw exec.constants::sig_msg_ptr mem_loadw_le
                swapw
                exec.sig::verify_signature_from_map
            end
        end
    ";

    let test = build_test!(source, &stack, &[], store, advice_map);
    test.execute()
        .expect("MASM shared-message batch verifier (2 distinct signers, map) failed");
}

#[test]
fn masm_verify_signature_single_query_slot0() {
    // Regression guard:
    // - catches DEEP formula/sign mistakes in single-query path
    // - catches OOD precompute layout/count mistakes (f_red(z), f_red(gz))
    let fixture = build_fixture(b"masm-single-query-slot0", 1010);

    let source = "
        use miden::core::sig
        use miden::core::sys
        use miden::core::sig::deep_queries
        begin
            exec.sig::verify_signature_setup
            push.0
            exec.deep_queries::verify_query_at_slot
            exec.sys::truncate_stack
        end
    ";

    let test = build_sig_test(source, &fixture.data);

    test.execute().expect("single-query verification for slot 0 failed");
}

#[test]
fn masm_deep_poly_layout_padded_descending() {
    use miden_processor::ContextId;

    const SIG_DEEP_POLY_PTR: u32 = 3240099976;
    const DEEP_EF_LOGICAL: usize = 118;
    const DEEP_EF_PADDED: usize = 128;
    const DEEP_ZERO_PREFIX: usize = DEEP_EF_PADDED - DEEP_EF_LOGICAL;

    let fixture = build_fixture(b"masm-deep-layout", 1011);
    let setup_source = "
        use miden::core::sig
        use miden::core::sys
        begin
            exec.sig::verify_signature_setup
            exec.sys::truncate_stack
        end
    ";
    let setup_test = build_sig_test(setup_source, &fixture.data);
    let (setup_output, _host) = setup_test.execute_for_output().expect("setup execution failed");
    let ctx = ContextId::root();

    // First 10 extension coefficients are padding zeros.
    for j in 0..DEEP_ZERO_PREFIX {
        let addr0 = SIG_DEEP_POLY_PTR + (2 * j as u32);
        let addr1 = addr0 + 1;
        let c0 = setup_output
            .memory
            .read_element(ctx, Felt::from_u32(addr0))
            .expect("missing deep coeff (lo)")
            .as_canonical_u64();
        let c1 = setup_output
            .memory
            .read_element(ctx, Felt::from_u32(addr1))
            .expect("missing deep coeff (hi)")
            .as_canonical_u64();
        assert_eq!(c0, 0, "expected zero-padded DEEP lo coeff at slot {j}");
        assert_eq!(c1, 0, "expected zero-padded DEEP hi coeff at slot {j}");
    }

    // Remaining coefficients must be in descending degree order: c117..c0.
    for j in 0..DEEP_EF_LOGICAL {
        let mem_slot = DEEP_ZERO_PREFIX + j;
        let coeff_idx = DEEP_EF_LOGICAL - 1 - j;
        let expected = ef_to_felts(&fixture.proof.deep_coeffs[coeff_idx]);

        let addr0 = SIG_DEEP_POLY_PTR + (2 * mem_slot as u32);
        let addr1 = addr0 + 1;
        let got0 = setup_output
            .memory
            .read_element(ctx, Felt::from_u32(addr0))
            .expect("missing deep coeff (lo)")
            .as_canonical_u64();
        let got1 = setup_output
            .memory
            .read_element(ctx, Felt::from_u32(addr1))
            .expect("missing deep coeff (hi)")
            .as_canonical_u64();
        assert_eq!(
            got0,
            expected[0].as_canonical_u64(),
            "DEEP lo coeff mismatch at memory slot {mem_slot}"
        );
        assert_eq!(
            got1,
            expected[1].as_canonical_u64(),
            "DEEP hi coeff mismatch at memory slot {mem_slot}"
        );
    }
}
