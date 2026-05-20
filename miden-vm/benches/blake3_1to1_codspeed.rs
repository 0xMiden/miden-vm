//! Native CodSpeed harness for the Blake3 1-to-1 proving benchmark.

use codspeed::codspeed::{CodSpeed, black_box, display_native_harness};
use miden_core::Felt;
use miden_core_lib::CoreLibrary;
use miden_vm::{
    Assembler, DefaultHost, ExecutionOptions, HashFunction, ProvingOptions, StackInputs,
    advice::AdviceInputs, prove_sync,
};

const SOURCE: &str = include_str!("../masm-examples/hashing/blake3_1to1/blake3_1to1.masm");

fn main() {
    display_native_harness();

    let program = {
        let mut assembler = Assembler::default();
        assembler
            .link_dynamic_library(CoreLibrary::default())
            .expect("failed to load core library");
        assembler.assemble_program(SOURCE).expect("failed to assemble blake3_1to1")
    };

    let mut codspeed = CodSpeed::new();
    codspeed.start_benchmark("blake3_1to1/prove");

    let mut host = DefaultHost::default()
        .with_library(&CoreLibrary::default())
        .expect("failed to load core library into host");
    let stack = [Felt::new_unchecked(u64::from(u32::MAX)); 8];
    let stack_inputs = StackInputs::new(&stack).expect("valid stack inputs");
    let advice_inputs = AdviceInputs::default()
        .with_stack_values([100_u64])
        .expect("valid advice inputs");
    let execution_options = ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        false,
        false,
    )
    .expect("valid execution options");

    black_box(
        prove_sync(
            &program,
            stack_inputs,
            advice_inputs,
            &mut host,
            execution_options,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        )
        .expect("prove blake3_1to1"),
    );

    codspeed.end_benchmark();
}
