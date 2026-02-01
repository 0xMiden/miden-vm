//! Synthetic transaction kernel benchmark
//!
//! This benchmark generates and executes a Miden program that mirrors
//! the instruction mix and operation profile of the real transaction kernel.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use miden_core_lib::CoreLibrary;
use miden_processor::fast::FastProcessor;
use miden_vm::{Assembler, DefaultHost, StackInputs};
use synthetic_tx_kernel::{generator::MasmGenerator, load_profile};

fn synthetic_transaction_kernel(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthetic_transaction_kernel");

    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(10));

    // Load the VM profile using CARGO_MANIFEST_DIR for crate-relative path
    let profile_path = format!("{}/profiles/latest.json", env!("CARGO_MANIFEST_DIR"));
    let profile = load_profile(&profile_path)
        .expect("Failed to load VM profile. Run miden-base bench-transaction first.");

    println!("Loaded profile from: {}", profile.source);
    println!("Miden VM version: {}", profile.miden_vm_version);
    println!("Total cycles in reference: {}", profile.transaction_kernel.total_cycles);

    // Generate the synthetic kernel
    let total_cycles_expected = profile.transaction_kernel.total_cycles;
    let generator = MasmGenerator::new(profile);
    let source = generator.generate_kernel().expect("Failed to generate synthetic kernel");

    // Write the generated code for inspection (only if MASM_WRITE env var is set)
    if std::env::var("MASM_WRITE").is_ok() {
        std::fs::write("target/synthetic_kernel.masm", &source)
            .expect("Failed to write generated kernel");
    }

    // Assemble with core library (create one instance and reuse it)
    let core_lib = CoreLibrary::default();
    let mut assembler = Assembler::default();
    assembler
        .link_dynamic_library(core_lib.clone())
        .expect("Failed to load core library");

    let program = assembler
        .assemble_program(&source)
        .expect("Failed to assemble synthetic kernel");

    group.bench_function("execute", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_batched(
            || {
                let host = DefaultHost::default()
                    .with_library(&core_lib)
                    .expect("Failed to initialize host with core library");
                let processor = FastProcessor::new_with_advice_inputs(
                    StackInputs::default(),
                    miden_processor::AdviceInputs::default(),
                );
                (host, program.clone(), processor)
            },
            |(mut host, program, processor)| async move {
                black_box(processor.execute(&program, &mut host).await.unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, synthetic_transaction_kernel);
criterion_main!(benches);
