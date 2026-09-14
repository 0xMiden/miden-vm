//! Caller-state preservation by the recursive verifier entrypoints.

use miden_core::{Word, advice::AdviceInputs};
use miden_core_lib::CoreLibrary;
use miden_precompiles_verifier::masm_verifier::PvmRecursiveVerifierInputs;
use miden_processor::advice::AdviceStack;

use super::{
    EXAMPLE_FIB_KERNEL_SMALL, KERNEL_ODD_NUM_PROC, fib_stack_inputs,
    generate_recursive_verifier_data,
};

const CALLER_ADDRESSES: [u32; 4] = [
    3_223_322_628, // stark::constants::NUM_QUERIES_PTR
    3_223_322_776, // sys::vm::layout::CLAIM_COMMITMENT_PTR
    3_225_426_416, // sys::pvm::layout::PUBLIC_INPUTS_PTR
    2_147_483_648, // Initial local-memory base.
];

#[test]
fn mvm_verifier_preserves_caller_state() {
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_ODD_NUM_PROC),
    );
    let advice = AdviceInputs::default()
        .with_stack(AdviceStack::try_from_values(data.proof_stream).unwrap())
        .with_map(data.advice_map)
        .with_merkle_store(data.store);
    check_caller_state("vm", data.claim_commitment, advice, 4);
}

#[test]
fn pvm_verifier_preserves_caller_state() {
    let core_lib = CoreLibrary::default();
    let proof = super::pvm_verifier::prove_keccak_claim(b"PVM caller-state preservation");
    let inputs =
        PvmRecursiveVerifierInputs::for_request(core_lib.pvm_recursive_verifier_root(), &proof)
            .expect("the PVM fixture must adapt to recursive-verifier advice");
    let (advice, claim) = inputs.into_parts();
    let (mut stack, mut map, store) = advice.into_parts();
    let key = miden_core::program::proof_request_key(core_lib.pvm_recursive_verifier_root(), claim);
    let stream = map.remove(&key).expect("the proof package must contain its stream");
    stack.append_elements(stream.iter().copied());
    check_caller_state("pvm", claim, AdviceInputs::new(stack, map, store), 3);
}

fn check_caller_state(relation: &str, claim: Word, advice: AdviceInputs, output_words: usize) {
    let claim_pushes: String = claim.iter().rev().map(|value| format!("push.{value} ")).collect();
    let drop_outputs = "dropw ".repeat(output_words);

    // A 21-element tail spans the top sixteen elements and overflow and is not word-aligned.
    let caller_values = 101..122;
    let pushes: String =
        caller_values.clone().rev().map(|value| format!("push.{value} ")).collect();
    let checks: String = caller_values
        .map(|value| format!("eq.{value} assert.err=\"caller stack value {value} changed\"\n"))
        .collect();
    let stores = store_sentinels(7301);
    let memory_checks = check_sentinels(7301);
    let root_stores = store_sentinels(9101);
    let root_memory_checks = check_sentinels(9101);
    let source = format!(
        "
        use miden::core::sys::{relation}

        proc check_caller
            {pushes}
            {stores}
            {claim_pushes}
            exec.{relation}::verify_proof
            {drop_outputs}
            {checks}
            {memory_checks}
            sdepth eq.16 assert.err=\"unexpected caller stack depth\"
        end

        begin
            {root_stores}
            call.check_caller
            {root_memory_checks}
            sdepth eq.16 assert.err=\"unexpected root stack depth\"
            repeat.16 assertz.err=\"unexpected return value\" end
        end
        "
    );
    let mut test = build_debug_test!(source.as_str());
    test.advice_inputs = advice;
    test.prove_and_verify(Vec::new(), false);
}

fn store_sentinels(value: u32) -> String {
    CALLER_ADDRESSES
        .iter()
        .map(|addr| format!("push.{value} mem_store.{addr} "))
        .collect()
}

fn check_sentinels(value: u32) -> String {
    CALLER_ADDRESSES
        .iter()
        .map(|addr| {
            format!(
                "mem_load.{addr} eq.{value} assert.err=\"memory at {addr} must equal {value}\"\n"
            )
        })
        .collect()
}
