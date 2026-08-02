//! End-to-end verification of a real PVM proof inside MASM.

use std::sync::Arc;

use miden_core::{
    Felt,
    crypto::hash::Keccak256,
    deferred::{DeferredRoot, DeferredState, Node, PrecompileRegistry},
    proof::{DeferredProof, HashFunction, StarkProof},
};
use miden_core_lib::CoreLibrary;
use miden_precompiles::Keccak256Precompile;
use miden_precompiles_prover::{
    masm_verifier::{MasmVerifierInputError, MasmVerifierInputs, generate_masm_verifier_inputs},
    prove_deferred_state,
};
use miden_processor::ExecutionOutput;
use miden_utils_testing::recursive_verifier::VerifierData;

use super::{EXAMPLE_FIB_SMALL, fib_stack_inputs, generate_recursive_verifier_data};

#[test]
fn pvm_verifies_distinct_orders_and_coexists_with_the_vm() {
    let (short_proof, short_root) = prove_keccak_claim(b"PVM MASM verifier end-to-end fixture");
    let short = generate_masm_verifier_inputs(&short_proof, short_root)
        .expect("host adapter must parse the short proof");

    let mut suffixed_bytes = short_proof.bytes().to_vec();
    suffixed_bytes.push(0xaa);
    let suffixed_proof = StarkProof::new(suffixed_bytes, HashFunction::Poseidon2);
    assert!(
        matches!(
            generate_masm_verifier_inputs(&suffixed_proof, short_root),
            Err(MasmVerifierInputError::ProofDeserialization(_)),
        ),
        "the host adapter must reject trailing proof bytes"
    );

    let long_message = vec![0xa5; 4096];
    let (long_proof, long_root) = prove_keccak_claim(&long_message);
    let long = generate_masm_verifier_inputs(&long_proof, long_root)
        .expect("host adapter must parse the long proof");

    assert_ne!(
        pvm_order_tag(&short),
        pvm_order_tag(&long),
        "fixtures must exercise distinct registry leaves",
    );
    let short_output =
        run_pvm_verifier(&short).expect("PVM MASM verifier must accept the short proof");
    assert_pvm_security_params(&short, &short_output);
    let long_output =
        run_pvm_verifier(&long).expect("PVM MASM verifier must accept the long proof");
    assert_pvm_security_params(&long, &long_output);

    let mut wrong_root = *short.initial_stack();
    wrong_root[0] ^= 1;
    assert!(
        run_pvm_verifier_with_stack(&short, &wrong_root).is_err(),
        "the proof must not authenticate a different deferred root",
    );

    let mut wrong_shape = short.clone();
    wrong_shape.advice_stack[4] += 1;
    assert!(
        run_pvm_verifier(&wrong_shape).is_err(),
        "the proof must not authenticate different trace-shape metadata",
    );

    for index in 0..4 {
        let mut wrong_params = short.clone();
        wrong_params.advice_stack[index] ^= 1;
        assert!(
            run_pvm_verifier(&wrong_params).is_err(),
            "security parameter {index} must be bound into the transcript",
        );
    }

    let mut corrupt_circuit = short.clone();
    let circuit_stream = &mut corrupt_circuit
        .advice_map
        .last_mut()
        .expect("adapter appends the selected ACE stream")
        .1;
    circuit_stream[0] = Felt::from_u8((circuit_stream[0].as_canonical_u64() == 0) as u8);
    assert!(
        run_pvm_verifier(&corrupt_circuit).is_err(),
        "the selected ACE instruction stream must be authenticated",
    );

    let vm = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    run_interleaved_verifiers(&vm, &short)
        .expect("VM/PVM/VM/PVM verification must not leak shared scratch state");
}

#[test]
fn pvm_proof_package_can_be_fetched_by_content() {
    let (proof, root) = prove_keccak_claim(b"content-addressed PVM proof fixture");
    let direct =
        generate_masm_verifier_inputs(&proof, root).expect("host adapter must parse proof");
    let verifier_root = CoreLibrary::default().pvm_recursive_verifier_root();
    let package = direct
        .clone()
        .into_request_package(verifier_root)
        .expect("generated advice values must be canonical");

    let source = "
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
    let test = build_test!(
        source,
        package.initial_stack(),
        &package.advice_stack,
        package.store,
        package.advice_map,
    );
    let (output, _) = test.execute_for_output().expect("fetched PVM proof must verify");
    assert_pvm_security_params(&direct, &output);
}

fn prove_keccak_claim(input: &[u8]) -> (StarkProof, DeferredRoot) {
    let registry =
        Arc::new(PrecompileRegistry::new().with_precompile(Keccak256Precompile::default()));
    let mut state =
        DeferredState::new(registry, usize::MAX).expect("Keccak fixture registry must initialize");

    let input_digest = state
        .register(Node::chunks_from_bytes(input))
        .expect("input chunks must register");
    let digest_bytes: [u8; 32] = Keccak256::hash(input).into();
    let digest_chunk = core::array::from_fn(|i| {
        Felt::from_u32(u32::from_le_bytes(
            digest_bytes[4 * i..4 * i + 4].try_into().expect("one u32 limb"),
        ))
    });
    let expected_digest = state
        .register(Node::chunks([digest_chunk]).expect("digest chunk is non-empty"))
        .expect("expected digest must register");
    let assertion = state
        .register(Keccak256Precompile::assert_node(
            u32::try_from(input.len()).expect("fixture length fits u32"),
            input_digest,
            expected_digest,
        ))
        .expect("matching Keccak assertion must register");
    let root = state.log_statement(assertion).expect("true statement must log");

    let deferred = prove_deferred_state(&state, HashFunction::Poseidon2)
        .expect("fixture must produce a PVM STARK proof");
    match deferred {
        DeferredProof::Stark { proof, public_root } => {
            assert_eq!(public_root, root, "proof envelope must bind the logged root");
            (proof, public_root)
        },
        DeferredProof::Empty | DeferredProof::Wire(_) => {
            panic!("non-empty fixture must produce a STARK-backed deferred proof")
        },
    }
}

fn run_pvm_verifier(
    inputs: &MasmVerifierInputs,
) -> Result<ExecutionOutput, miden_processor::ExecutionError> {
    run_pvm_verifier_with_stack(inputs, inputs.initial_stack())
}

fn run_pvm_verifier_with_stack(
    inputs: &MasmVerifierInputs,
    initial_stack: &[u64; 4],
) -> Result<ExecutionOutput, miden_processor::ExecutionError> {
    let source = "
        use miden::core::sys
        use miden::core::sys::pvm
        begin
            exec.pvm::verify_proof
            exec.sys::truncate_stack
        end
    ";
    let test = build_test!(
        source,
        initial_stack,
        &inputs.advice_stack,
        inputs.store.clone(),
        inputs.advice_map.clone(),
    );
    test.execute_for_output().map(|(output, _)| output)
}

fn assert_pvm_security_params(inputs: &MasmVerifierInputs, output: &ExecutionOutput) {
    let mut expected: Vec<Felt> =
        inputs.advice_stack[..4].iter().copied().map(Felt::new_unchecked).collect();
    // The root occupied the next stack word before verification. Requiring zero padding beneath
    // the returned parameters proves that the verifier consumed it instead of returning it too.
    expected.extend([Felt::ZERO; 4]);
    assert_eq!(
        output.stack.get_num_elements(expected.len()),
        expected,
        "the verifier must consume the root and return only its transcript-bound security parameters",
    );
}

fn pvm_order_tag(inputs: &MasmVerifierInputs) -> u32 {
    const SECURITY_PARAM_COUNT: usize = 4;
    const NUM_CHIPLETS: usize = 10;

    let heights = &inputs.advice_stack[SECURITY_PARAM_COUNT..SECURITY_PARAM_COUNT + NUM_CHIPLETS];
    let mut proof_order: Vec<usize> = (0..NUM_CHIPLETS).collect();
    proof_order.sort_by_key(|&i| (heights[i], i));
    miden_ace_codegen::order_tag(&proof_order)
}

fn run_interleaved_verifiers(
    vm: &VerifierData,
    pvm: &MasmVerifierInputs,
) -> Result<(), miden_processor::ExecutionError> {
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(vm.advice_stack());
    advice_stack.extend_from_slice(&pvm.advice_stack);
    advice_stack.extend_from_slice(vm.advice_stack());
    advice_stack.extend_from_slice(&pvm.advice_stack);

    let mut store = vm.store.clone();
    store.extend(pvm.store.inner_nodes());
    let mut advice_map = vm.advice_map.clone();
    advice_map.extend_from_slice(&pvm.advice_map);

    let vm_operands = push_operands(&vm.initial_stack());
    let pvm_operands = push_operands(pvm.initial_stack());
    let source = format!(
        "
        use miden::core::sys::pvm
        use miden::core::sys::vm

        proc verify_vm
            exec.vm::verify_vm_proof
            dropw dropw
        end

        begin
            {vm_operands}
            exec.verify_vm
            {pvm_operands}
            exec.pvm::verify_proof
            dropw
            {vm_operands}
            exec.verify_vm
            {pvm_operands}
            exec.pvm::verify_proof
            dropw
        end
        "
    );
    let test = build_test!(source, &[], &advice_stack, store, advice_map);
    test.execute().map(|_| ())
}

/// Push values in reverse so `values[0]` becomes the top operand, matching
/// `StackInputs::try_from_ints`.
fn push_operands(values: &[u64]) -> String {
    values.iter().rev().map(|value| format!("push.{value}\n")).collect()
}
