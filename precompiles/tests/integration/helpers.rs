use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, deferred::DeferredState};
use miden_precompiles::{PrecompilesLibrary, registry};
use miden_processor::{
    ContextId, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor,
    StackInputs, advice::AdviceInputs,
};

pub const IN_PTR: u32 = 128;
pub const OUT_PTR: u32 = 256;

pub fn run_precompile_program(source: &str) -> Result<ExecutionOutput, ExecutionError> {
    run_precompile_program_with_stack(source, &[])
}

pub fn run_precompile_program_with_stack(
    source: &str,
    stack: &[Felt],
) -> Result<ExecutionOutput, ExecutionError> {
    let stack_inputs = StackInputs::new(stack).expect("invalid precompile test stack inputs");
    let library = PrecompilesLibrary::default();
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program("precompile_test", source)
        .expect("failed to assemble precompile test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&library)
        .expect("failed to load PrecompilesLibrary into the host");

    let output = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(registry())?
    .execute_sync(&program, &mut host);

    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "precompile wrappers must consume advice");
    }

    output
}

pub fn read_memory_felts(output: &ExecutionOutput, ptr: u32, len: usize) -> Vec<Felt> {
    (0..len as u32)
        .map(|i| {
            output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(ptr + i))
                .expect("memory element")
        })
        .collect()
}

pub fn masm_store_felts(felts: &[Felt], base_addr: u32) -> String {
    felts
        .iter()
        .enumerate()
        .map(|(i, felt)| {
            format!("push.{} push.{} mem_store", felt.as_canonical_u64(), base_addr + i as u32)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn masm_push_u32x8(limbs: [u32; 8]) -> String {
    let limbs = limbs.map(Felt::from_u32);
    format!("push.{}", felt_list(&limbs))
}

pub fn assert_deferred_state_round_trips(output: &ExecutionOutput) {
    let registry = Arc::new(registry());
    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    let rehydrated = DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX)
        .expect("deferred wire must rehydrate under miden-precompiles registry");
    assert_eq!(
        rehydrated.root(),
        output.deferred_state.root(),
        "wire round-trip must preserve the deferred root"
    );
}

fn felt_list(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".")
}
