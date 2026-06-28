use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, deferred::DeferredState};
use miden_precompiles::{PrecompilesLibrary, registry};
use miden_processor::{
    ContextId, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor,
    StackInputs, advice::AdviceInputs,
};

pub type U32x8 = [u32; 8];

pub const IN_PTR: u32 = 128;
pub const OUT_PTR: u32 = 256;

pub const TRUNCATE_STACK_TO_OUTPUT_PROC: &str = "
@locals(4)
proc truncate_stack_to_output
     loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end
";

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

pub fn expect_precompile_trap(source: &str) -> ExecutionError {
    run_precompile_program(source).expect_err("expected precompile program to trap")
}

pub fn read_stack_felts(output: &ExecutionOutput, len: usize) -> Vec<Felt> {
    (0..len).map(|i| output.stack.get_element(i).expect("stack element")).collect()
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

pub fn assert_stack_u32x8(output: &ExecutionOutput, expected: U32x8) {
    assert_eq!(read_stack_u32x8(output), expected);
}

pub fn assert_memory_u32x8(output: &ExecutionOutput, ptr: u32, expected: U32x8) {
    assert_eq!(read_memory_u32x8(output, ptr), expected);
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

pub fn masm_store_u32x8(limbs: U32x8, base_addr: u32) -> String {
    let limbs = limbs.map(Felt::from_u32);
    masm_store_felts(&limbs, base_addr)
}

pub fn masm_push_u32x8(limbs: U32x8) -> String {
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

fn read_stack_u32x8(output: &ExecutionOutput) -> U32x8 {
    felts_to_u32x8(read_stack_felts(output, 8))
}

fn read_memory_u32x8(output: &ExecutionOutput, ptr: u32) -> U32x8 {
    felts_to_u32x8(read_memory_felts(output, ptr, 8))
}

fn felts_to_u32x8(felts: Vec<Felt>) -> U32x8 {
    core::array::from_fn(|i| {
        felts[i].as_canonical_u64().try_into().expect("u32x8 limb must fit in u32")
    })
}

fn felt_list(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".")
}
