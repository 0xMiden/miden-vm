use std::vec::Vec;

use super::*;

fn engine() -> ReplEngine {
    ReplEngine::new(Box::new(DebuggerConfig {
        input: Some(crate::program_loader::test_package_input()),
        ..Default::default()
    }))
    .unwrap()
}

fn execute(engine: &mut ReplEngine, command: &str) -> String {
    let mut output = Vec::new();
    assert_eq!(engine.execute_line(command, &mut output).unwrap(), Outcome::Continue);
    String::from_utf8(output).unwrap()
}

#[test]
fn inspection_commands_report_initial_and_completed_state() {
    let mut engine = engine();
    assert_eq!(engine.make_prompt(false), "[cycle 0 STOP] > ");
    assert!(engine.make_prompt(true).contains("\x1b[1;33mSTOP"));
    assert_eq!(execute(&mut engine, "stack"), "Stack is empty\n");
    assert!(execute(&mut engine, "vars all").contains("No debug variables tracked"));
    assert!(execute(&mut engine, "locals").contains("No debug variables tracked"));
    assert!(execute(&mut engine, "where").contains("No current frame"));
    assert!(execute(&mut engine, "list").contains("No current frame"));
    assert!(execute(&mut engine, "bt").contains("No call stack"));
    assert!(execute(&mut engine, "help").contains("Available commands:"));

    execute(&mut engine, "step 2");
    assert_eq!(engine.state().executor().cycle, 2);
    assert!(execute(&mut engine, "where").contains("in "));
    assert!(execute(&mut engine, "bt").contains("Backtrace ("));
    assert!(execute(&mut engine, "list").contains("Recent instructions:"));
    assert!(execute(&mut engine, "frame 0").contains("in "));
    assert_eq!(engine.state.selected_stack_frame(), 0);

    assert!(execute(&mut engine, "continue").contains("Program terminated successfully"));
    assert!(engine.state().executor().stopped);
    assert!(engine.make_prompt(false).contains("END"));
    assert!(engine.make_prompt(true).contains("\x1b[1;32mEND"));
    assert!(execute(&mut engine, "stack").contains("[0] 7 (0x7)"));
    assert!(!execute(&mut engine, "vars all").contains("="));
}

#[test]
fn breakpoint_commands_add_list_delete_and_stop_execution() {
    let mut engine = engine();
    assert_eq!(execute(&mut engine, "bp"), "No breakpoints set\n");
    assert_eq!(execute(&mut engine, "b at 3"), "Breakpoint 0 set: at cycle 3\n");
    assert_eq!(execute(&mut engine, "b after 5"), "Breakpoint 1 set: after 5 cycles\n");
    let listing = execute(&mut engine, "bp");
    assert!(listing.contains("[0] at cycle 3"));
    assert!(listing.contains("[1] after 5 cycles"));
    execute(&mut engine, "c");
    assert_eq!(engine.state().executor().cycle, 3);
    assert!(!engine.state().executor().stopped);
    assert_eq!(execute(&mut engine, "d 1"), "Deleted breakpoint 1\n");
    assert_eq!(execute(&mut engine, "d"), "Deleted all breakpoints\n");
    assert!(engine.state().breakpoints.iter().all(|bp| bp.is_internal()));
    assert!(engine.execute_line("d 99", &mut Vec::new()).unwrap_err().contains("99"));
}

#[test]
fn resume_commands_and_reload_reset_execution() {
    for command in ["next", "next-line", "finish"] {
        let mut engine = engine();
        execute(&mut engine, command);
        assert!(engine.state().executor().cycle > 0);
        execute(&mut engine, "reload");
        assert_eq!(engine.state().executor().cycle, 0);
        assert!(!engine.state().executor().stopped);
        assert_eq!(engine.state.selected_stack_frame(), 0);
    }
}

#[test]
fn invalid_commands_and_terminated_execution_are_rejected() {
    let mut engine = engine();
    assert!(engine.execute_line("unknown", &mut Vec::new()).is_err());
    assert!(
        engine
            .execute_line("frame 99", &mut Vec::new())
            .unwrap_err()
            .contains("invalid frame index")
    );
    assert_eq!(engine.execute_line("quit", &mut Vec::new()).unwrap(), Outcome::Quit);
    execute(&mut engine, "step 100");
    assert!(engine.state().executor().stopped);
    for command in ["continue", "next", "next-line", "finish", "step"] {
        assert!(
            engine
                .execute_line(command, &mut Vec::new())
                .unwrap_err()
                .contains("terminated")
        );
    }
}

#[test]
fn memory_commands_and_empty_stack_have_explicit_output() {
    let mut engine = engine();
    execute(&mut engine, "continue");
    assert!(!execute(&mut engine, "mem 0 -t u32").is_empty());
    engine.state_mut().executor_mut().current_stack.clear();
    assert_eq!(execute(&mut engine, "stack"), "Stack is empty\n");
}

#[test]
fn failed_execution_is_reported_in_output_and_prompt() {
    use std::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::serde::Serializable;

    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("failure", "begin push.0 assert end")
        .unwrap();
    let mut engine = ReplEngine::new(Box::new(DebuggerConfig {
        input: Some(crate::InputFile::new("stdin://", Some(package.to_bytes().into_boxed_slice()))),
        ..Default::default()
    }))
    .unwrap();
    let output = execute(&mut engine, "step 100");
    assert!(output.contains("Program terminated with error:"));
    assert!(engine.state().execution_failed().is_some());
    assert!(engine.make_prompt(false).contains("ERR"));
    assert!(engine.make_prompt(true).contains("\x1b[1;31mERR"));
}

#[test]
fn breakpoint_descriptions_cover_each_supported_kind() {
    for (spec, expected) in [
        ("after 2", "after 2 cycles"),
        ("at 3", "at cycle 3"),
        ("in entrypoint", "call *::entrypoint"),
        ("main.rs:8", "**/main.rs:8"),
        ("main.rs", "**/main.rs"),
        ("for add", "opcode add"),
    ] {
        assert_eq!(format_bp_type(&spec.parse().unwrap()), expected);
    }
    for (kind, expected) in [
        (BreakpointType::Step, "next cycle"),
        (BreakpointType::Next, "next instruction"),
        (BreakpointType::NextLine, "next source line"),
        (BreakpointType::Finish, "function return"),
    ] {
        assert_eq!(format_bp_type(&kind), expected);
    }
}
