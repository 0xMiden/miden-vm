//! End-to-end verification of a real PVM proof inside MASM.

use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    advice::{AdviceInputs, AdviceStack},
    crypto::hash::Keccak256,
    deferred::{
        DEFERRED_AND_FRAME, DeferredState, Node, PrecompileWitness, PrecompileWitnessEntry,
        deferred_chunks_frame,
    },
    program::proof_request_key,
    proof::{HashFunction, PrecompileProof, StarkProof},
    serde::Deserializable,
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::{
    CoreLibrary,
    dsa::{ecdsa_p256_sha256, eddsa_25519_sha512},
};
use miden_crypto::dsa::eddsa_25519_sha512::SigningKey as Ed25519SigningKey;
use miden_precompiles::{Keccak256Precompile, Sha256Precompile, Sha512Precompile};
use miden_precompiles_air::NUM_CHIPLETS;
use miden_precompiles_prover::prove_precompiles;
use miden_precompiles_verifier::masm_verifier::{
    PvmRecursiveVerifierInputs, PvmRecursiveVerifierInputsError,
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, StackInputs,
    operation::OperationError,
};
use miden_utils_testing::recursive_verifier::VerifierData;

use super::{
    EXAMPLE_FIB_SMALL, fib_stack_inputs, generate_recursive_verifier_data,
    verifier_stack::{CALLER_WORD, VERIFIER_RETURN, VerifierStack},
};
use crate::{
    helpers::{masm_push_word, masm_store_felts},
    support::ecdsa::valid_fixture,
};

const SECURITY_PARAM_COUNT: usize = 4;

/// A Keccak-only proof still pays every chiplet's fixed verifier cost, which bounds its recursive
/// trace at 2^19 rows. Tightening this to 2^18 is tracked in
/// <https://github.com/0xMiden/miden-vm/issues/3863>.
#[test]
fn pvm_keccak_only_recursive_verifier_cost_is_bounded() {
    const SOURCE: &str = "
        use miden::core::sys
        use miden::core::sys::pvm
        begin
            dupw
            procref.pvm::verify_proof
            exec.sys::build_proof_request_key
            adv.push_mapval dropw
            exec.pvm::verify_proof
            exec.sys::truncate_stack
        end
    ";

    let proof = prove_keccak_claim(&[0x61; 32]);
    let inputs = PvmRecursiveVerifierInputs::for_request(pvm_verify_proof_root(), &proof)
        .expect("host adapter must parse the proof");
    let initial_stack: [u64; 4] = inputs.claim_commitment().into();
    let mut test = build_test!(SOURCE, initial_stack);
    test.advice_inputs = inputs.advice().clone();
    let trace = test.execute().expect("Keccak-only PVM proof must verify");
    let summary = trace.trace_len_summary();
    eprintln!("Keccak-only PVM recursive trace: {summary:?}");
    assert!(
        summary.padded_trace_len() <= 1 << 19,
        "the fixed SHA programs must not force Keccak-only recursion past 2^19 rows"
    );
}

#[test]
fn pvm_verifies_sha512_and_mixed_hash_claims() {
    use miden_crypto::hash::sha2::Sha512;

    for mixed in [false, true] {
        let mut state = DeferredState::new(Arc::new(miden_precompiles::registry())).unwrap();
        // 112 bytes requires two SHA-512 padding blocks; Keccak still needs only one.
        let input = [0xa5; 112];
        let preimage = state.register(Node::chunks_from_bytes(&input)).unwrap();
        let expected = state
            .register(Node::chunks_from_bytes(Sha512::hash(&input).as_bytes()))
            .unwrap();
        let assertion =
            state.register(Sha512Precompile::assert_node(112, preimage, expected)).unwrap();
        state.log_statement(assertion).unwrap();
        if mixed {
            let expected = state
                .register(Node::chunks_from_bytes(Keccak256::hash(&input).as_bytes()))
                .unwrap();
            let assertion = state
                .register(Keccak256Precompile::assert_node(112, preimage, expected))
                .unwrap();
            state.log_statement(assertion).unwrap();
        }
        let witness = state.into_witness().unwrap().expect("the state logs hash claims");
        let proof = prove_precompiles(vec![witness], HashFunction::Eidos).unwrap();
        let inputs =
            PvmRecursiveVerifierInputs::for_request(pvm_verify_proof_root(), &proof).unwrap();
        assert_pvm_verifies(&inputs);
    }
}

#[test]
fn pvm_verifies_sha256_claims() {
    use miden_crypto::hash::sha2::Sha256;

    let mut state = DeferredState::new(Arc::new(miden_precompiles::registry())).unwrap();
    // 56 bytes pushes the length field into a second SHA-256 padding block.
    let input = [0x5a; 56];
    let preimage = state.register(Node::chunks_from_bytes(&input)).unwrap();
    let expected = state
        .register(Node::chunks_from_bytes(Sha256::hash(&input).as_bytes()))
        .unwrap();
    let assertion = state.register(Sha256Precompile::assert_node(56, preimage, expected)).unwrap();
    state.log_statement(assertion).unwrap();
    let witness = state.into_witness().unwrap().expect("the state logs a hash claim");
    let proof = prove_precompiles(vec![witness], HashFunction::Eidos).unwrap();
    let inputs = PvmRecursiveVerifierInputs::for_request(pvm_verify_proof_root(), &proof).unwrap();
    assert_pvm_verifies(&inputs);
}

/// One PVM proof of a core-library execution that exercises every deferred precompile: ECDSA
/// secp256k1 verification (Keccak and a secp256k1 MSM), Ed25519 verification (SHA-512 and an
/// Ed25519 MSM), ECDSA P-256 verification (SHA-256 and a P-256 MSM), and SHA-256 at its
/// padding boundaries and across multiple blocks.
#[test]
fn pvm_verifies_a_session_mixing_every_precompile() {
    const SHA256_LENGTHS: [usize; 6] = [0, 55, 56, 64, 120, 1000];
    // Each message gets its own zero-initialized buffer, so every final chunk is zero-padded.
    const SHA256_BUFFER_BASE: u32 = 1 << 12;
    const SHA256_BUFFER_STRIDE: u32 = 1 << 8;

    let core_lib = CoreLibrary::default();
    let k256 = valid_fixture();
    let ed25519_key = Ed25519SigningKey::read_from_bytes(&[0xed; 32]).unwrap();
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();

    let mut sha256_calls = String::new();
    for (index, len) in SHA256_LENGTHS.into_iter().enumerate() {
        let message: Vec<u8> =
            (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect();
        let ptr = SHA256_BUFFER_BASE + SHA256_BUFFER_STRIDE * index as u32;
        sha256_calls.push_str(&format!(
            "{stores}\n            push.{ptr} push.{len} push.{ptr}\n            \
             exec.::miden::core::precompiles::hashes::sha256::hash_bytes_mem\n            ",
            stores = masm_store_felts(&bytes_to_packed_u32_elements(&message), ptr),
        ));
    }
    let source = format!(
        "
        begin
            {message}
            {k256_commitment}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify
            {message}
            {ed25519_commitment}
            exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify
            {message}
            {p256_commitment}
            exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::verify
            {sha256_calls}
        end
        ",
        message = masm_push_word(&k256.message),
        k256_commitment = masm_push_word(&k256.public_key_commitment),
        ed25519_commitment =
            masm_push_word(&eddsa_25519_sha512::public_key_commitment(&ed25519_key.public_key())),
        p256_commitment =
            masm_push_word(&ecdsa_p256_sha256::public_key_commitment(p256_key.verifying_key())),
    );
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("pvm_mixed_session", source)
        .unwrap()
        .unwrap_program();
    let mut advice = AdviceStack::new();
    advice.append_elements(k256.advice);
    advice.append_elements(eddsa_25519_sha512::sign(&ed25519_key, k256.message));
    advice.append_elements(ecdsa_p256_sha256::sign(&p256_key, k256.message));
    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();
    let output = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_stack(advice),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_sync(&program, &mut host)
    .expect("the mixed execution must succeed");
    assert!(output.advice.stack().is_empty(), "the execution must consume its advice");

    let proof = prove_precompiles(
        vec![output.precompile_witness.clone().expect("the execution logs deferred claims")],
        HashFunction::Eidos,
    )
    .expect("the mixed session must be provable");
    assert_eq!(proof.roots, [output.precompile_root()], "the proof must cover the execution");
    let inputs = PvmRecursiveVerifierInputs::for_request(pvm_verify_proof_root(), &proof).unwrap();
    assert_pvm_verifies(&inputs);
}

#[test]
fn pvm_verifies_distinct_orders_and_coexists_with_the_vm() {
    let verifier_root = pvm_verify_proof_root();
    let short_proof = prove_keccak_claim(b"PVM MASM verifier end-to-end fixture");
    let short = PvmRecursiveVerifierInputs::for_request(verifier_root, &short_proof)
        .expect("host adapter must parse the short proof");

    let mut suffixed_bytes = short_proof.proof.bytes().to_vec();
    suffixed_bytes.push(0xaa);
    let suffixed_proof = PrecompileProof {
        proof: StarkProof::new(suffixed_bytes, HashFunction::Eidos),
        roots: short_proof.roots,
    };
    assert!(
        matches!(
            PvmRecursiveVerifierInputs::for_request(verifier_root, &suffixed_proof),
            Err(PvmRecursiveVerifierInputsError::ProofDeserialization(_)),
        ),
        "the host adapter must reject trailing proof bytes"
    );

    let long_message = vec![0xa5; 4096];
    let long_proof = prove_keccak_claim(&long_message);
    let long = PvmRecursiveVerifierInputs::for_request(verifier_root, &long_proof)
        .expect("host adapter must parse the long proof");

    assert_ne!(
        pvm_proof_order(&short),
        pvm_proof_order(&long),
        "fixtures must exercise distinct proof orders",
    );
    assert_pvm_verifies(&short);
    assert_pvm_verifies(&long);
    assert_pvm_rejects_tampering(&short);

    let vm = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    run_interleaved_verifiers(&vm, &short)
        .expect("VM/PVM/VM/PVM verification must not leak shared scratch state");
}

fn assert_pvm_rejects_tampering(inputs: &PvmRecursiveVerifierInputs) {
    let verifier_root = pvm_verify_proof_root();
    let mut wrong_claim_elements: [u64; 4] = inputs.claim_commitment().into();
    wrong_claim_elements[0] ^= 1;
    let wrong_claim_commitment =
        Word::try_from(wrong_claim_elements).expect("mutated claim is canonical");
    let (stack, mut map, store) = inputs.advice().clone().into_parts();
    let request_key = proof_request_key(verifier_root, inputs.claim_commitment());
    let proof_stream = map
        .remove(&request_key)
        .expect("PVM request package must contain its proof stream");
    map.insert(proof_request_key(verifier_root, wrong_claim_commitment), proof_stream);
    let wrong_claim_advice = AdviceInputs::new(stack, map, store);
    assert_pvm_rejects(&wrong_claim_advice, wrong_claim_commitment);

    // The twelve heights are the sole carrier of proof order into the OOD scatter table, the sigma
    // scatter, and fold staging. Chiplet 3's height is verifier-fixed (its stream slot must equal
    // a constant, so forging it fails a shape check rather than exercising order binding); every
    // other chiplet's height is advice-supplied and must be transcript-bound.
    const FIXED_CHIPLET: usize = 3;

    let honest_order = pvm_proof_order(inputs);
    let mut reordering_forgeries = 0usize;
    for chiplet in (0..NUM_CHIPLETS).filter(|&chiplet| chiplet != FIXED_CHIPLET) {
        let mut wrong_shape = inputs.advice().clone();
        mutate_proof_stream(inputs, &mut wrong_shape, |stream| {
            stream[SECURITY_PARAM_COUNT + chiplet] += Felt::ONE;
        });

        let mut forged_heights: Vec<Felt> = self::proof_stream(inputs)
            [SECURITY_PARAM_COUNT..SECURITY_PARAM_COUNT + NUM_CHIPLETS]
            .to_vec();
        forged_heights[chiplet] += Felt::ONE;
        let mut forged_order: Vec<usize> = (0..NUM_CHIPLETS).collect();
        forged_order.sort_by_key(|&i| (forged_heights[i].as_canonical_u64(), i));
        if forged_order != honest_order {
            reordering_forgeries += 1;
        }

        assert_pvm_rejects(&wrong_shape, inputs.claim_commitment());
    }
    assert!(
        reordering_forgeries > 0,
        "no forged height moved the proof order, so this fixture cannot cover order binding"
    );

    for index in 0..SECURITY_PARAM_COUNT {
        let mut wrong_params = inputs.advice().clone();
        mutate_proof_stream(inputs, &mut wrong_params, |stream| {
            stream[index] += Felt::ONE;
        });
        assert_pvm_rejects(&wrong_params, inputs.claim_commitment());
    }

    let (stack, mut map, store) = inputs.advice().clone().into_parts();
    let (circuit_key, circuit_values) = map
        .iter()
        .filter(|(key, _)| **key != request_key)
        .max_by_key(|(_, values)| values.len())
        .map(|(key, values)| (*key, values.to_vec()))
        .expect("adapter must include the selected ACE stream");
    let stream_blocks: usize = include_str!("../../asm/sys/pvm/constraints_eval.masm")
        .lines()
        .find_map(|line| line.trim().strip_prefix("const ACE_STREAM_BLOCKS = ")?.parse().ok())
        .expect("the generated PVM evaluator declares its stream length");
    assert_eq!(
        circuit_values.len(),
        8 * stream_blocks,
        "the largest content-addressed value must be the ACE instruction stream"
    );
    let mut circuit_stream = circuit_values;
    circuit_stream[0] = Felt::from_u8((circuit_stream[0].as_canonical_u64() == 0) as u8);
    map.insert(circuit_key, circuit_stream);
    let corrupt_circuit = AdviceInputs::new(stack, map, store);
    assert_pvm_rejects(&corrupt_circuit, inputs.claim_commitment());
}

pub(super) fn prove_keccak_claim(input: &[u8]) -> PrecompileProof {
    let input_node = Node::chunks_from_bytes(input);
    let digest_bytes: [u8; 32] = Keccak256::hash(input).into();
    let digest_chunk = core::array::from_fn(|i| {
        Felt::from_u32(u32::from_le_bytes(
            digest_bytes[4 * i..4 * i + 4].try_into().expect("one u32 limb"),
        ))
    });
    let assertion = Keccak256Precompile::assert_node(
        u32::try_from(input.len()).expect("fixture length fits u32"),
        input_node.digest(),
        Node::chunks([digest_chunk]).unwrap().digest(),
    );
    let witness = PrecompileWitness::from_entries(vec![
        PrecompileWitnessEntry::Data {
            frame: deferred_chunks_frame(
                u32::try_from(input_node.payload().as_data().unwrap().len())
                    .expect("fixture chunk count fits u32"),
            ),
            chunks: input_node.payload().as_data().unwrap().to_vec(),
        },
        PrecompileWitnessEntry::Data {
            frame: deferred_chunks_frame(1),
            chunks: vec![digest_chunk],
        },
        PrecompileWitnessEntry::Join {
            frame: assertion.frame().expect("assertion nodes carry a frame"),
            lhs: 1,
            rhs: 2,
        },
        PrecompileWitnessEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 3,
        },
    ])
    .expect("Keccak fixture has a canonical portable graph");
    prove_precompiles(vec![witness], HashFunction::Eidos)
        .expect("fixture must produce a PVM STARK proof")
}

fn run_pvm_verifier_with_advice(
    advice: &AdviceInputs,
    claim_commitment: Word,
) -> Result<VerifierStack, ExecutionError> {
    let request_key = proof_request_key(pvm_verify_proof_root(), claim_commitment);
    assert!(
        advice.map().contains_key(&request_key),
        "test advice must contain the proof stream for the supplied claim"
    );
    let source = format!(
        "
        use miden::core::sys
        use miden::core::sys::pvm

        const VERIFIER_RETURN = event(\"{VERIFIER_RETURN}\")

        begin
            dupw
            procref.pvm::verify_proof
            exec.sys::build_proof_request_key
            adv.push_mapval dropw
            exec.pvm::verify_proof
            # => [security_descriptor(12), ...]
            trace.VERIFIER_RETURN
            exec.sys::truncate_stack
        end
    "
    );
    let claim_elements: [u64; 4] = claim_commitment.into();
    let mut initial_stack = claim_elements.to_vec();
    initial_stack.extend(CALLER_WORD);
    let verifier_stack = VerifierStack::default();
    let mut test = build_test!(source, initial_stack)
        .with_trace_handler(VERIFIER_RETURN, verifier_stack.clone());
    test.advice_inputs = advice.clone();
    test.execute_for_output()?;
    Ok(verifier_stack)
}

#[track_caller]
fn assert_pvm_verifies(inputs: &PvmRecursiveVerifierInputs) {
    use miden_precompiles_air::security;

    let verifier_stack = run_pvm_verifier_with_advice(inputs.advice(), inputs.claim_commitment())
        .expect("PVM MASM verifier rejected a valid proof");

    let stream = proof_stream(inputs);
    let log_max_height = stream[SECURITY_PARAM_COUNT..SECURITY_PARAM_COUNT + NUM_CHIPLETS]
        .iter()
        .map(Felt::as_canonical_u64)
        .max()
        .expect("the PVM relation has chiplet AIRs");
    let expected = [
        u64::from(security::LOOKUP_POW_BITS),
        u64::from(security::AIR_SHAPE.num_composed_constraints),
        u64::from(security::AIR_SHAPE.max_constraint_degree),
        u64::from(security::AIR_SHAPE.num_deep_terms.unwrap()),
        u64::from(security::AIR_SHAPE.lookup.max_message_width),
        u64::from(security::FIXED_BOUNDARY_LOOKUP_TERMS),
        u64::from(security::AIR_SHAPE.lookup.fractions_per_row),
        log_max_height,
        stream[0].as_canonical_u64(),
        stream[1].as_canonical_u64(),
        stream[2].as_canonical_u64(),
        stream[3].as_canonical_u64(),
    ];
    verifier_stack.assert_outputs_and_caller(&expected);
}

#[track_caller]
fn assert_pvm_rejects(advice: &AdviceInputs, claim_commitment: Word) {
    let error = run_pvm_verifier_with_advice(advice, claim_commitment)
        .expect_err("PVM MASM verifier accepted an invalid proof");
    assert!(
        matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { .. },
                ..
            }
        ),
        "expected the PVM verifier to fail an assertion, got {error:?}",
    );
}

/// The chiplet instances in committed-trace order: ascending log height, instance index breaking
/// ties.
fn pvm_proof_order(inputs: &PvmRecursiveVerifierInputs) -> Vec<usize> {
    let heights = &proof_stream(inputs)[SECURITY_PARAM_COUNT..SECURITY_PARAM_COUNT + NUM_CHIPLETS];
    let mut proof_order: Vec<usize> = (0..NUM_CHIPLETS).collect();
    proof_order.sort_by_key(|&i| (heights[i].as_canonical_u64(), i));
    proof_order
}

fn run_interleaved_verifiers(
    vm: &VerifierData,
    pvm: &PvmRecursiveVerifierInputs,
) -> Result<(), ExecutionError> {
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(vm.advice_stack());
    advice_stack.extend(proof_stream(pvm).iter().map(Felt::as_canonical_u64));
    advice_stack.extend_from_slice(vm.advice_stack());
    advice_stack.extend(proof_stream(pvm).iter().map(Felt::as_canonical_u64));

    let mut store = vm.store.clone();
    store.extend(pvm.advice().store().inner_nodes());
    let mut advice_map = vm.advice_map.clone();
    advice_map.extend(pvm.advice().map().iter().map(|(key, values)| (*key, values.to_vec())));

    let vm_operands = masm_push_word(&vm.claim_commitment);
    let pvm_operands = masm_push_word(&pvm.claim_commitment());
    let source = format!(
        "
        use miden::core::sys::pvm
        use miden::core::sys::vm

        proc verify_mvm
            exec.vm::verify_proof
            dropw dropw dropw dropw
        end

        begin
            {vm_operands}
            exec.verify_mvm
            {pvm_operands}
            exec.pvm::verify_proof
            dropw dropw dropw
            {vm_operands}
            exec.verify_mvm
            {pvm_operands}
            exec.pvm::verify_proof
            dropw dropw dropw
        end
        "
    );
    let test = build_test!(source, &[], &advice_stack, store, advice_map);
    test.execute().map(|_| ())
}

fn pvm_verify_proof_root() -> Word {
    CoreLibrary::default().pvm_recursive_verifier_root()
}

fn proof_stream(inputs: &PvmRecursiveVerifierInputs) -> &[Felt] {
    inputs
        .advice()
        .map()
        .get(&proof_request_key(pvm_verify_proof_root(), inputs.claim_commitment()))
        .expect("PVM request package must contain its proof stream")
}

fn mutate_proof_stream(
    inputs: &PvmRecursiveVerifierInputs,
    advice: &mut AdviceInputs,
    mutate: impl FnOnce(&mut Vec<Felt>),
) {
    let key = proof_request_key(pvm_verify_proof_root(), inputs.claim_commitment());
    let (stack, mut map, store) = core::mem::take(advice).into_parts();
    let mut stream = map
        .remove(&key)
        .expect("PVM request package must contain its proof stream")
        .to_vec();
    mutate(&mut stream);
    map.insert(key, stream);
    *advice = AdviceInputs::new(stack, map, store);
}
