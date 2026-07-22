//! The overlapped execute-and-build path must produce exactly the trace the
//! buffered path produces: same values, byte for byte, in every segment.

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
    trace::build_trace,
};

/// A program mixing basic blocks (including repeats, which exercise the
/// hasher's memoized-trace path), control blocks, and enough work to spread
/// over multiple trace fragments.
const PROGRAM: &str = "
begin
    push.1 push.2
    repeat.8
        u32wrapping_add dup.1 swap
        push.3 u32and drop
    end
    if.true
        push.5 mul
    else
        push.7 add
    end
    repeat.4
        push.11 u32wrapping_add
    end
    drop
end
";

fn processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::new(&[miden_processor::Felt::new_unchecked(1)]).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .unwrap()
}

#[test]
fn overlapped_build_matches_buffered() {
    let program = Assembler::default().assemble_program("test", PROGRAM).unwrap().unwrap_program();

    let buffered = {
        let mut host = DefaultHost::default();
        let inputs = processor().execute_trace_inputs_sync(&program, &mut host).unwrap();
        build_trace(inputs).unwrap()
    };

    let streamed = {
        let mut host = DefaultHost::default();
        processor().execute_and_build_trace_sync(&program, &mut host).unwrap()
    };

    assert_eq!(buffered.program_hash(), streamed.program_hash());
    let (b_core, b_chiplets, b_p2) = buffered.main_trace().to_air_matrices();
    let (s_core, s_chiplets, s_p2) = streamed.main_trace().to_air_matrices();
    assert_eq!(b_core, s_core, "core segment diverged");
    assert_eq!(b_chiplets, s_chiplets, "chiplets segment diverged");
    assert_eq!(b_p2, s_p2, "poseidon2 segment diverged");
}
