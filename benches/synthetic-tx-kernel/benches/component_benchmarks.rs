//! Component-level benchmarks for individual operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use miden_vm::{Assembler, DefaultHost, StackInputs};
use miden_processor::fast::FastProcessor;
use miden_core_lib::CoreLibrary;
use synthetic_tx_kernel::{load_profile, generator::MasmGenerator};

fn benchmark_signature_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verification");

    // Load profile to get realistic iteration counts
    let profile = load_profile("profiles/latest.json").expect("Failed to load profile");
    let generator = MasmGenerator::new(profile);

    // Falcon512 verification benchmark
    group.bench_function("falcon512_verify", |b| {
        let source = generator.generate_component_benchmark("falcon512_verify", 1)
            .expect("Failed to generate benchmark");

        let program = Assembler::default()
            .assemble_program(&source)
            .expect("Failed to assemble");

        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_batched(
                || {
                    let host = DefaultHost::default();
                    let processor = FastProcessor::new(
                        StackInputs::default(),
                        miden_processor::AdviceInputs::default(),
                    );
                    (host, program.clone(), processor)
                },
                |(mut host, program, processor)| async move {
                    black_box(processor.execute(&program, &mut host).await.unwrap());
                },
                BatchSize::SmallInput,
            );
    });

    group.finish();
}

fn benchmark_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    group.bench_function("hperm", |b| {
        let source = r#"
            use.miden::core::sys
            begin
                repeat.100
                    hperm
                end
                exec.sys::truncate_stack
            end
        "#;

        let program = Assembler::default()
            .assemble_program(source)
            .expect("Failed to assemble");

        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_batched(
                || {
                    let host = DefaultHost::default();
                    let processor = FastProcessor::new(
                        StackInputs::default(),
                        miden_processor::AdviceInputs::default(),
                    );
                    (host, program.clone(), processor)
                },
                |(mut host, program, processor)| async move {
                    black_box(processor.execute(&program, &mut host).await.unwrap());
                },
                BatchSize::SmallInput,
            );
    });

    group.finish();
}

fn benchmark_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_operations");

    group.bench_function("load_store", |b| {
        let source = r#"
            use.miden::core::sys
            begin
                repeat.100
                    push.1 mem_storew
                    push.1 mem_loadw
                    dropw
                end
                exec.sys::truncate_stack
            end
        "#;

        let program = Assembler::default()
            .assemble_program(source)
            .expect("Failed to assemble");

        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_batched(
                || {
                    let host = DefaultHost::default();
                    let processor = FastProcessor::new(
                        StackInputs::default(),
                        miden_processor::AdviceInputs::default(),
                    );
                    (host, program.clone(), processor)
                },
                |(mut host, program, processor)| async move {
                    black_box(processor.execute(&program, &mut host).await.unwrap());
                },
                BatchSize::SmallInput,
            );
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_signature_verification,
    benchmark_hashing,
    benchmark_memory_operations
);
criterion_main!(benches);
