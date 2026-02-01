//! Component-level benchmarks for individual operations

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use miden_processor::fast::FastProcessor;
use miden_vm::{Assembler, DefaultHost, StackInputs};
use synthetic_tx_kernel::{generator::MasmGenerator, load_profile};

/// Helper function to execute a benchmark with the given program
fn bench_program(b: &mut criterion::Bencher, program: &miden_vm::Program) {
    b.to_async(tokio::runtime::Runtime::new().expect("Failed to create tokio runtime"))
        .iter_batched(
            || {
                let host = DefaultHost::default();
                let processor = FastProcessor::new_with_advice_inputs(
                    StackInputs::default(),
                    miden_processor::AdviceInputs::default(),
                );
                (host, processor)
            },
            |(mut host, processor)| async move {
                black_box(processor.execute(program, &mut host).await.unwrap());
            },
            BatchSize::SmallInput,
        );
}

fn benchmark_signature_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verification");

    // Load profile for signature verification benchmark
    let profile_path = format!("{}/profiles/latest.json", env!("CARGO_MANIFEST_DIR"));
    let profile = load_profile(&profile_path).expect("Failed to load profile");
    let generator = MasmGenerator::new(profile);

    // Falcon512 verification benchmark
    group.bench_function("falcon512_verify", |b| {
        let source = generator
            .generate_component_benchmark("falcon512_verify", 1)
            .expect("Failed to generate benchmark");

        let program = Assembler::default().assemble_program(&source).expect("Failed to assemble");
        bench_program(b, &program);
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

        let program = Assembler::default().assemble_program(source).expect("Failed to assemble");
        bench_program(b, &program);
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

        let program = Assembler::default().assemble_program(source).expect("Failed to assemble");
        bench_program(b, &program);
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
