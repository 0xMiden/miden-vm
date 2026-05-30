use miden_assembly::Assembler;
use miden_processor::{ExecutionOptions, Program, StackInputs, advice::AdviceInputs};

use super::TestHost;

fn exec_source(source: impl AsRef<str>) -> String {
    miden_utils_testing::executable_source(source)
}

#[test]
fn test_event_handling() {
    let source = "\
    begin
        push.1000
        emit
        drop
        push.2000
        emit
        drop
        swapw dropw
    end";

    // compile and execute program
    let program: Program = Assembler::default()
        .assemble_program("program", exec_source(source))
        .unwrap()
        .unwrap_program();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    // make sure events were handled correctly
    let expected = vec![1000, 2000];
    assert_eq!(host.event_handler, expected);
}
