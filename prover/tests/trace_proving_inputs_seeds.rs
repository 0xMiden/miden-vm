use std::{fs, path::Path};

use miden_assembly::Assembler;
use miden_processor::{DefaultHost, FastProcessor};
use miden_prover::{
    AdviceInputs, ExecutionOptions, ProvingOptions, StackInputs, TraceProvingInputs,
    serde::Serializable,
};

#[test]
#[ignore = "writes fuzz corpus seeds"]
fn generate_trace_proving_inputs_fuzz_seed() {
    let program = Assembler::default()
        .assemble_program(
            "trace_proving_inputs_seed",
            "
            begin
                push.1 drop
            end
            ",
        )
        .expect("failed to assemble seed program")
        .unwrap_program();

    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_core_trace_fragment_size(64).unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    let trace_inputs = processor
        .execute_trace_inputs_sync(&program, &mut host)
        .expect("seed program execution failed");

    let seed = TraceProvingInputs::new(trace_inputs, ProvingOptions::default()).to_bytes();
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../miden-core-fuzz/corpus/trace_proving_inputs_deserialize");
    fs::create_dir_all(&corpus_dir).expect("failed to create trace proving inputs corpus dir");
    fs::write(corpus_dir.join("valid-small.bin"), seed)
        .expect("failed to write trace proving inputs seed");
}
