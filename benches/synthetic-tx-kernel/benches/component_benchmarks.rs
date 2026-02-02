//! Component-level benchmarks for individual operations

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use miden_core::{Felt, Word};
use miden_core_lib::{CoreLibrary, dsa::falcon512_poseidon2};
use miden_processor::fast::FastProcessor;
use miden_processor::AdviceInputs;
use miden_vm::{Assembler, DefaultHost, StackInputs};
use synthetic_tx_kernel::{generator::MasmGenerator, load_profile};

/// Helper function to execute a benchmark with the given program
fn bench_program(
    b: &mut criterion::Bencher,
    program: &miden_vm::Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    load_core_lib: bool,
) {
    b.to_async(tokio::runtime::Runtime::new().expect("Failed to create tokio runtime"))
        .iter_batched(
            || {
                let mut host = DefaultHost::default();
                if load_core_lib {
                    host.load_library(&CoreLibrary::default())
                        .expect("Failed to load core library");
                }
                let processor = FastProcessor::new_with_advice_inputs(
                    stack_inputs,
                    advice_inputs.clone(),
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

        let program = Assembler::default()
            .with_dynamic_library(CoreLibrary::default())
            .expect("Failed to load core library")
            .assemble_program(&source)
            .expect("Failed to assemble");

        let secret_key = falcon512_poseidon2::SecretKey::new();
        let message = Word::new([
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
        ]);
        let public_key = secret_key.public_key().to_commitment();
        let signature = falcon512_poseidon2::sign(&secret_key, message)
            .expect("Failed to generate signature");

        let mut stack = Vec::with_capacity(8);
        stack.extend_from_slice(&public_key);
        stack.extend_from_slice(&message);
        let stack_inputs = StackInputs::new(&stack).expect("Failed to build stack inputs");
        let advice_inputs = AdviceInputs::default().with_stack(signature);

        bench_program(b, &program, stack_inputs, advice_inputs, true);
    });

    group.finish();
}

fn benchmark_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    group.bench_function("hperm", |b| {
        let source = r#"
            begin
                repeat.100
                    hperm
                end
            end
        "#;

        let program = Assembler::default().assemble_program(source).expect("Failed to assemble");
        bench_program(
            b,
            &program,
            StackInputs::default(),
            AdviceInputs::default(),
            false,
        );
    });

    group.finish();
}

fn benchmark_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_operations");

    group.bench_function("load_store", |b| {
        let source = r#"
            begin
                repeat.100
                    push.0 mem_storew_be
                    push.0 mem_loadw_be
                    dropw
                end
            end
        "#;

        let program = Assembler::default().assemble_program(source).expect("Failed to assemble");
        bench_program(
            b,
            &program,
            StackInputs::default(),
            AdviceInputs::default(),
            false,
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
