use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, deferred::DeferredState, utils::bytes_to_packed_u32_elements};
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::{keccak::Keccak256, sha2::Sha512};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, StackInputs,
    advice::AdviceInputs,
};

use crate::helpers::{masm_push_felts, masm_store_felts};

const IN_PTR: u32 = 128;

const TRUNCATE_STACK_TO_8_PROC: &str = r#"
@locals(8)
proc truncate_stack_to_8
    loc_storew_le.0 dropw
    loc_storew_le.4 dropw
    sdepth neq.16
    while.true
        drop
        sdepth neq.16
    end
    loc_loadw_le.4
    swapw
    loc_loadw_le.0
end
"#;

const TRUNCATE_STACK_TO_16_PROC: &str = r#"
@locals(16)
proc truncate_stack_to_16
    loc_storew_le.0 dropw
    loc_storew_le.4 dropw
    loc_storew_le.8 dropw
    loc_storew_le.12 dropw
    sdepth neq.16
    while.true
        drop
        sdepth neq.16
    end
    loc_loadw_le.12
    swapw.3
    loc_loadw_le.8
    swapw.2
    loc_loadw_le.4
    swapw
    loc_loadw_le.0
end
"#;

#[test]
fn core_keccak256_hash_bytes_returns_expected_digest() {
    let input = b"core hash compatibility";

    let output =
        run_core_hash_bytes("keccak256", input).expect("keccak256::hash_bytes must execute");
    assert_deferred_state_round_trips(&output);
    assert_eq!(read_stack_felts(&output, 8), pack_digest(&Keccak256::hash(input)));
}

#[test]
fn core_keccak256_hash_returns_expected_digest() {
    let input: Vec<u8> = (0u8..32).collect();

    let output = run_core_fixed_hash("keccak256", &input).expect("keccak256::hash must execute");
    assert_deferred_state_round_trips(&output);
    assert_eq!(read_stack_felts(&output, 8), pack_digest(&Keccak256::hash(&input)));
}

#[test]
fn core_keccak256_merge_returns_expected_digest() {
    let left: Vec<u8> = (0u8..32).collect();
    let right: Vec<u8> = (32u8..64).collect();
    let mut preimage = left.clone();
    preimage.extend_from_slice(&right);

    let output = run_core_merge(&left, &right).expect("keccak256::merge must execute");
    assert_deferred_state_round_trips(&output);
    assert_eq!(read_stack_felts(&output, 8), pack_digest(&Keccak256::hash(&preimage)));
}

#[test]
fn core_sha512_hash_bytes_returns_expected_digest() {
    let input = b"core hash compatibility";

    let output = run_core_hash_bytes("sha512", input).expect("sha512::hash_bytes must execute");
    assert_deferred_state_round_trips(&output);
    assert_eq!(read_stack_felts(&output, 16), pack_digest(&Sha512::hash(input)));
}

fn run_core_hash_bytes(module: &str, input: &[u8]) -> Result<ExecutionOutput, ExecutionError> {
    let input_felts = bytes_to_packed_u32_elements(input);
    let stores = masm_store_felts(&input_felts, IN_PTR);
    let truncate = truncate_proc_for_module(module);
    let truncate_call = truncate_call_for_module(module);
    let source = format!(
        r#"
        {truncate}

        begin
            {stores}
            push.{len_bytes}
            push.{IN_PTR}
            exec.::miden::core::crypto::hashes::{module}::hash_bytes
            exec.{truncate_call}
        end
        "#,
        len_bytes = input.len(),
    );

    run_core_program(&source)
}

fn run_core_fixed_hash(module: &str, input: &[u8]) -> Result<ExecutionOutput, ExecutionError> {
    assert_eq!(input.len(), 32, "fixed hash wrapper takes a 256-bit input");
    let input = masm_push_felts(&bytes_to_packed_u32_elements(input));
    let truncate = truncate_proc_for_module(module);
    let truncate_call = truncate_call_for_module(module);
    let source = format!(
        r#"
        {truncate}

        begin
            {input}
            exec.::miden::core::crypto::hashes::{module}::hash
            exec.{truncate_call}
        end
        "#,
    );

    run_core_program(&source)
}

fn run_core_merge(left: &[u8], right: &[u8]) -> Result<ExecutionOutput, ExecutionError> {
    assert_eq!(left.len(), 32, "merge left input must be 256 bits");
    assert_eq!(right.len(), 32, "merge right input must be 256 bits");

    let left = masm_push_felts(&bytes_to_packed_u32_elements(left));
    let right = masm_push_felts(&bytes_to_packed_u32_elements(right));
    let source = format!(
        r#"
        {TRUNCATE_STACK_TO_8_PROC}

        begin
            {right}
            {left}
            exec.::miden::core::crypto::hashes::keccak256::merge
            exec.truncate_stack_to_8
        end
        "#,
    );

    run_core_program(&source)
}

fn truncate_proc_for_module(module: &str) -> &'static str {
    match module {
        "keccak256" => TRUNCATE_STACK_TO_8_PROC,
        "sha512" => TRUNCATE_STACK_TO_16_PROC,
        _ => panic!("unsupported hash module {module}"),
    }
}

fn truncate_call_for_module(module: &str) -> &'static str {
    match module {
        "keccak256" => "truncate_stack_to_8",
        "sha512" => "truncate_stack_to_16",
        _ => panic!("unsupported hash module {module}"),
    }
}

fn run_core_program(source: &str) -> Result<ExecutionOutput, ExecutionError> {
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_hash_compat_test", source)
        .expect("failed to assemble core hash compatibility test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");

    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(miden_core_lib::precompiles::registry())?;

    let output = processor.execute_sync(&program, &mut host);
    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "core hash wrappers must consume advice");
    }

    output
}

fn read_stack_felts(output: &ExecutionOutput, len: usize) -> Vec<Felt> {
    (0..len).map(|i| output.stack.get_element(i).expect("stack element")).collect()
}

fn pack_digest(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

fn assert_deferred_state_round_trips(output: &ExecutionOutput) {
    let registry = Arc::new(miden_core_lib::precompiles::registry());
    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    let rehydrated = DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX)
        .expect("deferred wire must rehydrate under miden-core-lib precompiles registry");
    assert_eq!(
        rehydrated.root(),
        output.deferred_state.root(),
        "wire round-trip must preserve the deferred root",
    );
}
