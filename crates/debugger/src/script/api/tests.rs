use super::*;

#[test]
fn script_debugger_executes_commands_and_exposes_state() {
    let debugger = test_debugger();

    assert_eq!(debugger.cycle(), 0);

    let output = debugger.handle_command("step").unwrap();
    assert!(output.contains("in") || output.is_empty(), "unexpected output: {output}");
    assert_eq!(debugger.cycle(), 1);

    let stack_output = debugger.handle_command("stack").unwrap();
    assert!(stack_output.contains("Operand Stack"));
}

#[test]
fn script_debugger_can_manage_breakpoints() {
    let debugger = test_debugger();

    let bp = debugger.set_breakpoint("after 1").unwrap();
    assert_eq!(bp.id, 0);
    assert_eq!(debugger.breakpoints().len(), 1);

    debugger.delete_breakpoint(Some(bp.id)).unwrap();
    assert!(debugger.breakpoints().is_empty());
}

#[test]
fn script_execution_context_and_clones_follow_the_same_session() {
    let debugger = test_debugger();
    let cloned = debugger.clone();
    let initial = debugger.execution_context();
    assert_eq!(initial.cycle, 0);
    assert!(initial.stopped);
    assert!(!initial.terminated);
    assert!(initial.frame.variables.is_empty());
    assert!(debugger.stack().is_empty());
    assert!(
        debugger
            .source_path_prefixes()
            .contains(&miden_debug_engine::normalize_source_path(
                std::env::current_dir().unwrap().to_str().unwrap()
            ))
    );
    assert!(debugger.result().unwrap().is_none());
    debugger.step(2).unwrap();
    assert_eq!(cloned.cycle(), 2);
    assert_eq!(debugger.frame(), cloned.frame());
    assert!(debugger.frame_with_variables(true).variables.is_empty());
    assert!(debugger.continue_().unwrap().contains("terminated successfully"));
    assert!(cloned.terminated());
    assert_eq!(debugger.stack()[0], 7);
    assert!(debugger.execution_context().terminated);
    assert!(debugger.frame().variables.is_empty());
    assert!(debugger.handle_command("quit").unwrap_err().contains("quit requested"));
    assert!(debugger.step(1).unwrap_err().contains("terminated"));
    debugger.reload().unwrap();
    assert_eq!(cloned.cycle(), 0);
    assert!(!cloned.terminated());
}

#[test]
fn script_breakpoint_hits_and_deletion_preserve_internal_breakpoints() {
    let debugger = test_debugger();
    let breakpoint = debugger.set_breakpoint("at 3").unwrap();
    assert_eq!(breakpoint.spec, "at cycle 3");
    assert!(!breakpoint.internal);
    assert!(breakpoint.one_shot);
    debugger.continue_().unwrap();
    assert_eq!(debugger.cycle(), 3);
    assert_eq!(debugger.hit_breakpoints()[0].id, breakpoint.id);
    debugger.clear_hit_breakpoints();
    assert!(debugger.hit_breakpoints().is_empty());
    assert!(debugger.delete_breakpoint(Some(99)).unwrap_err().contains("99"));
    assert!(debugger.set_breakpoint("at invalid").is_err());
    debugger.delete_breakpoint(None).unwrap();
    assert!(debugger.breakpoints().is_empty());
    debugger.engine.borrow_mut().state_mut().create_breakpoint(BreakpointType::Step);
    debugger.delete_breakpoint(None).unwrap();
    assert!(!debugger.engine.borrow().state().breakpoints.is_empty());
    assert!(debugger.breakpoints().is_empty());
    assert_eq!(debugger.read_memory("0 -t u32").unwrap(), "0");
    assert!(debugger.read_memory("invalid").is_err());
}

#[test]
fn script_step_wrappers_advance_execution() {
    for operation in [ScriptDebugger::next, ScriptDebugger::next_line, ScriptDebugger::finish] {
        let debugger = test_debugger();
        operation(&debugger).unwrap();
        assert!(debugger.cycle() > 0);
    }
}

pub(crate) fn test_debugger() -> ScriptDebugger {
    let config = DebuggerConfig {
        input: Some(crate::program_loader::test_package_input()),
        ..Default::default()
    };
    ScriptDebugger::from_config(Box::new(config)).expect("test package should load")
}

#[test]
fn frame_selection_inspects_distinct_invocations_without_changing_current_frame() {
    let debugger = invocation_debugger();
    assert_eq!(debugger.frame().variables[0].value, Some(22));
    debugger.handle_command("frame 1").unwrap();
    assert_eq!(debugger.handle_command("vars all").unwrap().trim(), "n=11");
    // Existing current-frame snapshots continue to describe the executing invocation.
    assert_eq!(debugger.frame().variables[0].value, Some(22));
    let caller = debugger.frame_at(1, true).unwrap();
    assert!(caller.function_name.as_deref().unwrap().ends_with("::outer"));
    assert_eq!(caller.variables[0].value, Some(11));
    assert!(debugger.frame_at(99, true).is_none());
    debugger.finish().unwrap();
    assert_eq!(debugger.frame().variables[0].value, Some(11));
    assert_eq!(debugger.selected_frame_index(), 0);
}

pub(crate) fn invocation_debugger() -> ScriptDebugger {
    use miden_core::serde::Serializable;
    let package = crate::program_loader::invocation_test_package(None);
    let debugger = ScriptDebugger::new(Box::new(DebuggerConfig {
        input: Some(crate::InputFile::new("stdin://", Some(package.to_bytes().into_boxed_slice()))),
        ..Default::default()
    }))
    .unwrap();
    debugger.set_breakpoint("in *inner").unwrap();
    debugger.continue_().unwrap();
    debugger.delete_breakpoint(None).unwrap();
    debugger
}
