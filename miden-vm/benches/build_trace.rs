use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use miden_core_lib::CoreLibrary;
use miden_processor::{AdviceInputs, ExecutionOptions, fast::FastProcessor, parallel};
use miden_vm::{Assembler, DefaultHost, StackInputs, execute, internal::InputFile};
use tokio::runtime::Runtime;
use walkdir::WalkDir;

/// The size of each trace fragment (in rows) when executing programs for trace generation.
const TRACE_FRAGMENT_SIZE: usize = 4096;

/// Benchmark the execution of all the masm examples in the `masm-examples` directory.
fn build_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_trace");

    let masm_examples_dir = {
        let mut miden_dir = std::env::current_dir().unwrap();
        miden_dir.push("masm-examples");

        miden_dir
    };

    for entry in WalkDir::new(masm_examples_dir) {
        match &entry {
            Ok(entry) => {
                // if it's not a masm file, skip it.
                if !entry.file_type().is_file() || entry.path().extension().unwrap() != "masm" {
                    continue;
                }

                // if there's a `.inputs` file associated with this `.masm` file, use it as the
                // inputs.
                let (stack_inputs, advice_inputs) = match InputFile::read(&None, entry.path()) {
                    Ok(input_data) => {
                        let stack_inputs = input_data.parse_stack_inputs().unwrap();
                        let advice_inputs = input_data.parse_advice_inputs().unwrap();
                        (stack_inputs, advice_inputs)
                    },
                    Err(_) => (StackInputs::default(), AdviceInputs::default()),
                };

                // the name of the file without the extension
                let source = std::fs::read_to_string(entry.path()).unwrap();

                // Create a benchmark for the masm file
                let file_stem = entry.path().file_stem().unwrap().to_string_lossy();

                // BUILD_TRACE
                // --------------------------------
                group.bench_function(file_stem.clone(), |bench| {
                    let mut assembler = Assembler::default();
                    assembler
                        .link_dynamic_library(CoreLibrary::default())
                        .expect("failed to load core library");

                    let program = assembler
                        .assemble_program(&source)
                        .expect("Failed to compile test source.");
                    let stack_inputs: Vec<_> = stack_inputs.iter().rev().copied().collect();

                    bench.to_async(Runtime::new().unwrap()).iter_batched(
                        || {
                            let host = DefaultHost::default()
                                .with_library(&CoreLibrary::default())
                                .unwrap();

                            let processor = FastProcessor::new_with_options(
                                &stack_inputs,
                                advice_inputs.clone(),
                                ExecutionOptions::default()
                                    .with_core_trace_fragment_size(TRACE_FRAGMENT_SIZE)
                                    .unwrap(),
                            );

                            (host, program.clone(), processor)
                        },
                        |(mut host, program, processor)| async move {
                            let (execution_output, trace_generation_context) =
                                processor.execute_for_trace(&program, &mut host).await.unwrap();

                            let trace = parallel::build_trace(
                                execution_output,
                                trace_generation_context,
                                program.hash(),
                                program.kernel().clone(),
                            );
                            black_box(trace);
                        },
                        BatchSize::SmallInput,
                    );
                });

                // LEGACY EXECUTE
                // --------------------------------
                group.bench_function(format!("{file_stem}_legacy"), |bench| {
                    let mut assembler = Assembler::default();
                    assembler
                        .link_dynamic_library(CoreLibrary::default())
                        .expect("failed to load core library");

                    let program = assembler
                        .assemble_program(&source)
                        .expect("Failed to compile test source.");

                    bench.to_async(Runtime::new().unwrap()).iter_batched(
                        || {
                            let host = DefaultHost::default()
                                .with_library(&CoreLibrary::default())
                                .unwrap();
                            let advice_inputs = advice_inputs.clone();

                            (host, stack_inputs, advice_inputs, program.clone())
                        },
                        |(mut host, stack_inputs, advice_inputs, program)| async move {
                            let trace = execute(
                                &program,
                                stack_inputs,
                                advice_inputs,
                                &mut host,
                                ExecutionOptions::default(),
                            )
                            .await
                            .unwrap();
                            black_box(trace);
                        },
                        BatchSize::SmallInput,
                    );
                });
            },
            // If we can't access the entry, just skip it
            Err(err) => {
                eprintln!("Failed to access file: {entry:?} with error {err:?}");
                continue;
            },
        }
    }

    group.finish();
}

criterion_group!(benchmark, build_trace);
criterion_main!(benchmark);
