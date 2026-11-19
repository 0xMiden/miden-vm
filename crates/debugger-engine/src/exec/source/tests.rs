use miden_assembly::{Assembler, DefaultSourceManager};
use miden_assembly_syntax::{
    Parse,
    ast::{DebugVarLocation, Instruction, Op},
};
use miden_debug_types::Span;
use miden_mast_package::Package;
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use super::*;

#[test]
fn control_cycles_retain_source_without_emitting_operation_events() {
    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(
        "proc target push.7 nop drop end begin call.target end",
        false,
        manager.clone(),
    )
    .unwrap();
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                *instruction = Span::new(
                    instruction.span(),
                    Instruction::DebugVar(DebugVarInfo::new("n", DebugVarLocation::Stack(0))),
                );
            }
        }
    }
    let package: Arc<Package> =
        Arc::from(Assembler::new(manager).assemble_program("program", module).unwrap());
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut host = DefaultHost::default();
    let mut context = processor.get_initial_resume_context_for_package(package).unwrap();
    let control = loop {
        let source = SourceContext::new(&context);
        if source.cycle.control_flow_kind == Some(ControlFlowOp::Span)
            && source.asmop().is_some_and(|op| op.context_name().ends_with("::target"))
        {
            break source;
        }
        context = processor.step_sync(&mut host, context).unwrap().expect("target entry");
    };
    assert_eq!(control.cycle.control_flow_kind, Some(ControlFlowOp::Span));
    assert!(control.cycle.op.is_none());
    assert_eq!(control.asmop().unwrap().op().as_ref(), "push.7");
    assert!(control.executed_asmop().is_none());
    assert!(control.debug_vars().is_empty());

    let next = processor.step_sync(&mut host, context).unwrap().unwrap();
    let operation = SourceContext::new(&next);
    assert!(operation.cycle.op.is_some());
    assert_eq!(operation.executed_asmop().unwrap().op().as_ref(), "push.7");
    assert_eq!(operation.asmop().unwrap().location(), control.asmop().unwrap().location());
    assert!(operation.debug_vars().is_empty());
    assert_eq!(operation.source_operation(), control.source_operation());

    let mut context = next;
    let mut declarations = 0;
    loop {
        let source = SourceContext::new(&context);
        if source.cycle.op_idx.is_none() {
            assert!(source.debug_vars().is_empty(), "control cycles must not repeat declarations");
        }
        for variable in source.debug_vars() {
            assert_eq!(variable.name().as_ref(), "n");
            assert_eq!(source.executed_asmop().unwrap().op().as_ref(), "drop");
            declarations += 1;
        }
        let Some(next) = processor.step_sync(&mut host, context).unwrap() else {
            break;
        };
        context = next;
    }
    assert_eq!(declarations, 1);
}

#[test]
fn identical_executable_bodies_keep_the_selected_source_occurrence() {
    let package: Arc<Package> = Arc::from(
        Assembler::new(Arc::new(DefaultSourceManager::default()))
            .assemble_program(
                "program",
                "proc first push.7 drop end proc second push.7 drop end begin call.first \
                 call.second end",
            )
            .unwrap(),
    );
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut host = DefaultHost::default();
    let mut context = processor.get_initial_resume_context_for_package(package).unwrap();
    let mut observed = Vec::new();
    loop {
        let source = SourceContext::new(&context);
        if let Some(asmop) = source.executed_asmop()
            && asmop.op().as_ref() == "push.7"
        {
            observed.push((asmop.context_name().clone(), source.source_operation().unwrap().0));
        }
        let Some(next) = processor.step_sync(&mut host, context).unwrap() else {
            break;
        };
        context = next;
    }
    assert_eq!(
        observed.iter().map(|(name, _)| name.as_ref()).collect::<Vec<_>>(),
        ["::$exec::first", "::$exec::second"]
    );
    assert_ne!(observed[0].1, observed[1].1);
}

#[test]
fn stripped_programs_keep_execution_metadata_without_source_metadata() {
    let mut package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("program", "begin push.7 drop end")
        .unwrap();
    package.strip_debug_info().unwrap();
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut host = DefaultHost::default();
    let context = processor.get_initial_resume_context_for_package(Arc::from(package)).unwrap();
    let next = processor.step_sync(&mut host, context).unwrap().unwrap();
    let source = SourceContext::new(&next);
    assert!(source.cycle.op.is_some());
    assert!(source.debug_info().is_none());
    assert!(source.source_operation().is_none());
    assert!(source.asmop().is_none());
    assert!(source.executed_asmop().is_none());
    assert!(source.inline_frames().is_empty());
    assert!(source.debug_vars().is_empty());
}
