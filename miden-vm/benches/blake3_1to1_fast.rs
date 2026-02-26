use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use miden_core::Felt;
use miden_core_lib::CoreLibrary;
use miden_processor::{FastProcessor, advice::AdviceInputs};
use miden_vm::{Assembler, DefaultHost, StackInputs};
use tokio::runtime::Runtime;

fn blake3_1to1_fast(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_1to1_fast");

    // operand_stack: 8 words of 0xFFFFFFFF
    let stack_inputs =
        StackInputs::new(&[Felt::new(u64::from(u32::MAX)); 8]).unwrap();
    // advice_stack: 100 iterations
    let advice_inputs = AdviceInputs::default().with_stack([Felt::new(100)]);

    let mut assembler = Assembler::default();
    assembler
        .link_dynamic_library(CoreLibrary::default())
        .expect("failed to load core library");
    let program = assembler
        .assemble_program(BLAKE3_1TO1_MASM)
        .expect("Failed to compile test source.");

    group.bench_function("blake3_1to1", |bench| {
        bench.to_async(Runtime::new().unwrap()).iter_batched(
            || {
                let host =
                    DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
                let processor =
                    FastProcessor::new(stack_inputs).with_advice(advice_inputs.clone());
                (host, program.clone(), processor)
            },
            |(mut host, program, processor)| async move {
                processor.execute(&program, &mut host).await.unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

const BLAKE3_1TO1_MASM: &str = "\
use miden::core::crypto::hashes::blake3
use miden::core::sys

begin
    # Push the number of iterations on the stack, and assess if we should loop
    adv_push.1 dup neq.0

    while.true
        # Move loop counter down
        movdn.8

        # Execute blake3 hash function
        exec.blake3::hash

        # Decrement counter, and check if we loop again
        movup.8 sub.1 dup neq.0
    end

    # Drop counter
    drop

    # Truncate stack to make constraints happy
    exec.sys::truncate_stack
end
";


criterion_group!(benchmark, blake3_1to1_fast);
criterion_main!(benchmark);
