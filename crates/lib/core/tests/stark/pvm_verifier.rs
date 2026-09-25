//! End-to-end verification of a real PVM proof inside MASM.

use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    crypto::hash::Keccak256,
    deferred::{
        DEFERRED_AND_FRAME, Node, PrecompileWitness, PrecompileWitnessEntry, deferred_chunks_frame,
    },
    program::proof_request_key,
    proof::{HashFunction, PrecompileProof, StarkProof},
};
use miden_core_lib::CoreLibrary;
use miden_precompiles::Keccak256Precompile;
use miden_precompiles_air::NUM_CHIPLETS;
use miden_precompiles_prover::prove_precompiles;
use miden_precompiles_verifier::masm_verifier::{
    PvmRecursiveVerifierInputs, PvmRecursiveVerifierInputsError,
};
use miden_processor::{ExecutionError, operation::OperationError};
use miden_utils_testing::recursive_verifier::VerifierData;

use super::{
    EXAMPLE_FIB_SMALL, fib_stack_inputs, generate_recursive_verifier_data,
    verifier_stack::{CALLER_WORD, VERIFIER_RETURN, VerifierStack},
};
use crate::helpers::masm_push_word;

const SECURITY_PARAM_COUNT: usize = 4;

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

    // The ten heights are the sole carrier of proof order into the OOD scatter table, the sigma
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
        u64::from(security::LOOKUP_SHAPE.max_message_width),
        u64::from(security::FIXED_BOUNDARY_LOOKUP_TERMS),
        u64::from(security::LOOKUP_SHAPE.fractions_per_row),
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
