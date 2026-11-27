use std::sync::LazyLock;

use miden_core::{
    Word,
    advice::AdviceInputs,
    program::{Program, StackInputs, StackOutputs},
    serde::Deserializable,
};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionError, Processor};

pub(super) enum Relation {
    Vm,
    Pvm,
}

static VM_PROGRAM: LazyLock<Program> = LazyLock::new(|| {
    Program::read_from_bytes(include_bytes!(concat!(env!("OUT_DIR"), "/vm.masb")))
        .expect("build script produced a valid VM verifier program")
});
static PVM_PROGRAM: LazyLock<Program> = LazyLock::new(|| {
    Program::read_from_bytes(include_bytes!(concat!(env!("OUT_DIR"), "/pvm.masb")))
        .expect("build script produced a valid PVM verifier program")
});

pub(super) fn run(
    relation: Relation,
    commitment: Word,
    advice: AdviceInputs,
) -> Result<StackOutputs, ExecutionError> {
    let program = match relation {
        Relation::Vm => &*VM_PROGRAM,
        Relation::Pvm => &*PVM_PROGRAM,
    };
    let stack = StackInputs::new(commitment.as_elements()).expect("one word fits the input stack");
    let mut host = DefaultHost::default().with_library(CoreLibrary::default().mast_forest())?;
    Ok(Processor::new(program)
        .with_stack_inputs(stack)
        .with_advice(advice)
        .execute()
        .run_sync(&mut host)?
        .stack)
}
