//! Synthetic transaction kernel benchmark
//!
//! This benchmark generates and executes a Miden program that mirrors
//! the instruction mix and operation profile of the real transaction kernel.

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use miden_vm::{Assembler, DefaultHost, StackInputs};
use miden_processor::fast::FastProcessor;
use miden_core_lib::CoreLibrary;
use synthetic_tx_kernel::{load_profile, generator::MasmGenerator};
use std::time::Duration;

fn synthetic_transaction_kernel(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthetic_transaction_kernel");

    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(10));

    // Load the VM profile
    let profile = load_profile("profiles/latest.json")
        .expect("Failed to load VM profile. Run miden-base bench-transaction first.");

    println!("Loaded profile from: {}", profile.source);
    println!("Miden VM version: {}", profile.miden_vm_version);
    println!("Total cycles in reference: {}", profile.transaction_kernel.total_cycles);

    // Generate the synthetic kernel
    let generator = MasmGenerator::new(profile);
    let source = generator.generate_kernel()
        .expect("Failed to generate synthetic kernel");

    // Optionally write the generated code for inspection
    std::fs::write("target/synthetic_kernel.masm", &source)
        .expect("Failed to write generated kernel");

    // Assemble with core library
    let mut assembler = Assembler::default();
    assembler.link_dynamic_library(CoreLibrary::default())
        .expect("Failed to load core library");

    let program = assembler.assemble_program(&source)
        .expect("Failed to assemble synthetic kernel");

    group.bench_function("execute", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_batched(
                || {
                    let host = DefaultHost::default()
                        .with_library(&CoreLibrary::default())
                        .expect("Failed to initialize host with core library");
                    let processor = FastProcessor::new(
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
