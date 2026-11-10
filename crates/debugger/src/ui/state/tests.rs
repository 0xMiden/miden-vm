use super::*;

#[test]
fn memory_inspection_decodes_integer_widths_formats_and_reports_invalid_reads() {
    let mut state = state_with_variables(
        "begin push.4294967295 mem_store.0 push.1 mem_store.1 push.2 mem_store.2 push.3 \
         mem_store.3 end",
    );
    state.run_until_stopped();
    for (expression, expected) in [
        ("0 -t i1", "true"),
        ("0 -t i1 -f hex", "0x1"),
        ("0 -t i1 -f binary", "0b1"),
        ("0 -t i8", "-1"),
        ("0 -t u8", "255"),
        ("0 -t i16", "-1"),
        ("0 -t u16", "65535"),
        ("0 -t i32", "-1"),
        ("0 -t u32", "4294967295"),
        ("0 -t i64", "8589934591"),
        ("0 -t u64", "8589934591"),
        ("0 -t felt", "4294967295"),
        ("0 -t word", "[4294967295, 1, 2, 3]"),
        ("0 -t u8 -f hex", "0xff"),
        ("0 -t u8 -f binary", "0b11111111"),
        ("100 -t u32", "0"),
    ] {
        assert_eq!(
            state.read_memory(&expression.parse().unwrap()).unwrap(),
            expected,
            "{expression}"
        );
    }
    for (expression, expected) in [
        ("0 -t u32 -c 2", "-count"),
        ("1 -t felt -m byte", "element boundary"),
        ("1 -t word", "word boundary"),
        ("1 -t u16 -m byte", "unaligned reads"),
        ("0 -t i128", "not implemented"),
        ("4294967295 -t u64", "beyond end"),
    ] {
        assert!(
            state.read_memory(&expression.parse().unwrap()).unwrap_err().contains(expected),
            "{expression}"
        );
    }
    assert_eq!(state.selected_stack_frame(), 0);
    state.select_older_stack_frame();
    state.select_newer_stack_frame();
    assert_eq!(state.selected_stack_frame(), 0);
    assert!(state.execution_failed().is_none());
}

#[test]
fn source_candidates_keep_absolute_paths_and_apply_only_declared_prefixes() {
    assert_eq!(
        source_path_candidates("src/lib.rs", &["/workspace".into()]),
        vec![PathBuf::from("/workspace/src/lib.rs")]
    );
    assert!(source_path_candidates("/workspace/src/lib.rs", &["/workspace".into()]).is_empty());
    assert!(source_paths_match(
        "file:///workspace/src/lib.rs",
        "src/lib.rs",
        &["/workspace".into()]
    ));
    assert!(!source_paths_match(
        "/workspace2/src/lib.rs",
        "src/lib.rs",
        &["/workspace".into()]
    ));
    assert_eq!(
        strip_source_prefix("/workspace/src/lib.rs", "/workspace/"),
        Some("src/lib.rs".into())
    );
    assert!(is_compiler_generated_name("local12"));
    assert!(!is_compiler_generated_name("local_count"));
}

fn state_with_entry_variables(source: &str) -> State {
    use miden_assembly_syntax::{
        Parse,
        ast::{Block, DebugVarInfo, DebugVarLocation, Instruction, Op},
        debuginfo::Span,
    };

    fn inject_variables(block: &mut Block) {
        for operation in block.iter_mut() {
            if let Op::If {
                then_blk, else_blk, ..
            } = operation
            {
                inject_variables(then_blk);
                inject_variables(else_blk);
            }
            let Op::Inst(instruction) = operation else {
                continue;
            };
            let location = match instruction.inner() {
                Instruction::Nop => DebugVarLocation::Stack(0),
                Instruction::Not => DebugVarLocation::Unavailable,
                _ => continue,
            };
            *instruction = Span::new(
                SourceSpan::default(),
                Instruction::DebugVar(DebugVarInfo::new("n", location)),
            );
        }
    }
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(source, false, source_manager.clone()).unwrap();
    for procedure in module.procedures_mut() {
        inject_variables(procedure.body_mut());
    }
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", module)
        .unwrap();
    let executor = Executor::new(Vec::new()).into_debug(package.into(), source_manager.clone());
    let mut state = State::new_local(
        source_manager,
        Box::<DebuggerConfig>::default(),
        DebugMode::Program,
        LocalState {
            executor,
            execution_failed: None,
            typed_procedure: None,
        },
    );
    state.create_breakpoint("in *entrypoint".parse().unwrap());
    state
}

fn state_with_variables(source: &str) -> State {
    use miden_assembly_syntax::{
        Parse,
        ast::{DebugVarInfo, DebugVarLocation, Instruction, Op},
    };
    use miden_debug_types::Span;
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = source.replacen("begin", "begin push.7 nop nop drop", 1);
    let mut module = Parse::parse(&source, false, source_manager.clone()).unwrap();
    let mut declarations = 0;
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                let info = if declarations == 0 {
                    DebugVarInfo::new("answer", DebugVarLocation::Stack(0))
                } else {
                    DebugVarInfo::new("local0", DebugVarLocation::Const(Felt::from_u32(9)))
                };
                *instruction = Span::new(SourceSpan::default(), Instruction::DebugVar(info));
                declarations += 1;
            }
        }
    }
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", module)
        .unwrap();
    let mut executor = Executor::new(Vec::new()).into_debug(package.into(), source_manager.clone());
    while executor.debug_vars.variable_count() < 2 {
        executor.step().unwrap();
        assert!(!executor.stopped);
    }
    State::new_local(
        source_manager,
        Box::default(),
        DebugMode::Program,
        LocalState {
            executor,
            execution_failed: None,
            typed_procedure: None,
        },
    )
}

#[test]
fn completed_execution_has_no_live_variables() {
    let mut state = state_with_variables("begin push.1 drop end");

    assert_eq!(state.format_variables(false), "answer=7");
    assert_eq!(state.format_variables(true), "answer=7, local0=9");

    state.run_until_stopped();

    assert!(state.executor().stopped);
    assert!(state.execution_failed().is_none());
    assert!(!state.executor().debug_vars.has_variables());
    for show_all in [false, true] {
        assert!(state.current_variables(show_all).is_empty());
        assert_eq!(state.format_variables(show_all), "Program has terminated; no live variables");
    }
}

#[test]
fn failed_execution_preserves_variables_for_inspection() {
    let mut state = state_with_variables("begin push.0 assert end");

    state.run_until_stopped();

    assert!(state.executor().stopped);
    assert!(state.execution_failed().is_some());
    assert_eq!(state.current_variables(false).len(), 1);
    assert_eq!(state.current_variables(true).len(), 2);
    assert_eq!(state.format_variables(false), "answer=7");
    assert_eq!(state.format_variables(true), "answer=7, local0=9");
}

#[test]
fn selected_frame_locals_preserve_caller_values_across_calls() {
    for call in ["exec", "call"] {
        let mut state = state_with_entry_variables(&format!(
            "proc entrypoint push.22 nop drop push.3 drop end proc outer push.11 nop drop \
             {call}.entrypoint push.4 drop end begin exec.outer push.5 drop end"
        ));
        state.run_until_stopped();
        assert_eq!(state.format_variables(true), "n=22");
        state.select_older_stack_frame();
        assert_eq!(state.format_variables(true), "n=11", "{call} caller");
        state.select_newer_stack_frame();
        assert_eq!(state.format_variables(true), "n=22");
        state.breakpoints.clear();
        state.create_breakpoint(BreakpointType::Finish);
        state.run_until_stopped();
        assert_eq!(state.selected_stack_frame(), 0);
        assert_eq!(state.format_variables(true), "n=11", "{call} returned caller");
    }
}

#[test]
fn function_breakpoint_waits_for_entry_variables() {
    let mut state = state_with_entry_variables(
        "proc entrypoint push.2 push.3 add nop drop push.1 if.true push.1 drop end end begin \
         exec.entrypoint end",
    );
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert_eq!(state.breakpoints_hit.len(), 1);
    assert_eq!(state.format_variables(true), "n=5");
}

#[test]
fn function_breakpoint_does_not_wait_for_missing_variables() {
    let mut state = state_with_entry_variables(
        "proc entrypoint push.2 push.3 add drop end begin exec.entrypoint end",
    );
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert_eq!(state.breakpoints_hit.len(), 1);
    assert!(state.current_variables(true).is_empty());
}

#[test]
fn function_breakpoint_accepts_variables_without_resolved_source() {
    let mut state = state_with_entry_variables(
        "proc entrypoint push.2 push.3 add nop drop end begin exec.entrypoint end",
    );
    state.source_manager = Arc::new(DefaultSourceManager::default());
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert_eq!(state.breakpoints_hit.len(), 1);
    assert!(state.current_display_location().is_none());
    assert_eq!(state.format_variables(true), "n=5", "{:?}", state.logical_stack_frames());
}

#[test]
fn function_breakpoint_ignores_caller_variables_and_kills() {
    let mut state = state_with_entry_variables(
        "proc entrypoint push.2 not push.3 add nop drop end begin push.91 nop drop \
         exec.entrypoint end",
    );
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert_eq!(state.breakpoints_hit.len(), 1);
    assert_eq!(state.format_variables(true), "n=5");
}

#[test]
fn function_breakpoint_does_not_enter_branches_to_find_variables() {
    let mut state = state_with_entry_variables(
        "proc entrypoint push.0 if.true push.5 nop drop end push.1 drop end begin exec.entrypoint \
         end",
    );
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert_eq!(state.breakpoints_hit.len(), 1);
    assert!(state.current_variables(true).is_empty());
    assert_eq!(state.executor().current_op, Some(miden_processor::operation::Operation::Pad));
}

#[test]
fn successful_reload_epilogue_resets_stack_selection() {
    let config = DebuggerConfig {
        input: Some(crate::program_loader::test_package_input()),
        ..Default::default()
    };
    let mut state = State::new(Box::new(config)).expect("state should build");
    state.selected_stack_frame = 3;
    state.breakpoints_hit.push(Breakpoint::default());
    state.stopped = false;
    state.executor_mut().stopped = true;
    state.create_breakpoint(BreakpointType::Finish);
    assert!(!state.finish_targets.is_empty());

    state.finish_reload();

    assert!(!state.executor().stopped);
    assert_eq!(state.selected_stack_frame, 0);
    assert!(state.breakpoints_hit.is_empty());
    assert!(state.finish_targets.is_empty());
    assert!(state.stopped);
}

#[test]
fn finish_keeps_its_invocation_when_another_breakpoint_interrupts_it() {
    let mut state = state_inside_inner_for_finish();
    state.create_breakpoint(BreakpointType::Finish);
    state.create_breakpoint(BreakpointType::Step);
    state.run_until_stopped();
    assert!(state.current_procedure().unwrap().ends_with("::inner"));
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert!(state.current_procedure().unwrap().ends_with("::outer"));
    assert_eq!(state.logical_stack_frames().len(), 2);
}

fn state_inside_inner_for_finish() -> State {
    let mut state = state_with_variables(
        "proc inner push.7 drop push.6 drop end proc outer exec.inner push.8 drop end begin \
         exec.outer push.9 drop end",
    );
    while !state.executor().stopped {
        state.executor_mut().step().unwrap();
        if state
            .executor()
            .current_asmop
            .as_ref()
            .is_some_and(|op| op.op().as_ref() == "push.7")
        {
            break;
        }
    }
    assert!(!state.executor().stopped);
    state
}

#[test]
fn duplicate_finish_breakpoints_are_consumed_together() {
    let mut state = state_inside_inner_for_finish();
    state.create_breakpoint(BreakpointType::Finish);
    state.create_breakpoint(BreakpointType::Step);
    state.run_until_stopped();
    assert!(state.current_procedure().unwrap().ends_with("::inner"));

    state.create_breakpoint(BreakpointType::Finish);
    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert!(state.current_procedure().unwrap().ends_with("::outer"));
    assert!(state.breakpoints.is_empty(), "neither finish breakpoint may remain orphaned");
    assert!(state.finish_targets.is_empty());
    assert_eq!(state.breakpoints_hit.len(), 2);
    assert!(state.breakpoints_hit.iter().all(|bp| bp.ty == BreakpointType::Finish));
}

#[test]
fn deleted_finish_target_does_not_survive_breakpoint_id_reuse() {
    let mut state = state_inside_inner_for_finish();
    state.create_breakpoint(BreakpointType::Finish);
    let deleted = state.breakpoints.last().unwrap().clone();
    state.create_breakpoint(BreakpointType::Step);
    state.run_until_stopped();
    assert!(state.current_procedure().unwrap().ends_with("::inner"));

    state.breakpoints.retain(|bp| bp.id != deleted.id);
    state.next_breakpoint_id = deleted.id;
    state.create_breakpoint(BreakpointType::Finish);
    let replacement = state.breakpoints.last().unwrap().clone();
    assert_eq!(replacement.id, deleted.id);
    assert_ne!(replacement.creation_cycle, deleted.creation_cycle);

    state.run_until_stopped();
    assert!(!state.executor().stopped);
    assert!(state.current_procedure().unwrap().ends_with("::outer"));
    assert_eq!(state.breakpoints_hit, [replacement]);
    assert!(state.breakpoints.is_empty());
    assert!(state.finish_targets.is_empty(), "deleted targets must be pruned on resume");
}

#[test]
fn deleting_an_interrupted_finish_allows_execution_to_complete() {
    let mut state = state_inside_inner_for_finish();
    state.create_breakpoint(BreakpointType::Finish);
    state.create_breakpoint(BreakpointType::Step);
    state.run_until_stopped();
    state.breakpoints.clear();

    state.run_until_stopped();
    assert!(state.executor().stopped);
    assert!(state.breakpoints_hit.is_empty());
    assert!(state.finish_targets.is_empty());
}
