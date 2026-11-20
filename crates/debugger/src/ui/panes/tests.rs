use std::{boxed::Box, string::String, vec::Vec};

use miden_core::Felt;
use ratatui::{Terminal, backend::TestBackend, layout::Rect, prelude::Style};

use super::{
    Pane, breakpoints::BreakpointsPane, debug::DebugPane, disasm::DisassemblyPane,
    error::ErrorPane, footer::FooterPane, header::HeaderPane, stack::OperandStackPane,
    stacktrace::StackTracePane,
};
use crate::{
    config::DebuggerConfig,
    program_loader::test_package_input,
    ui::{action::Action, state::State},
};

fn state() -> State {
    State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .expect("test state should build")
}

fn render_pane<P: Pane + ?Sized>(pane: &mut P, state: &State, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal should build");
    terminal
        .draw(|frame| {
            pane.draw(frame, Rect::new(0, 0, width, height), state)
                .expect("pane should render");
        })
        .expect("pane should render");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer.cell((x, y)).expect("cell should exist").symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn renders_header_and_error_popup() {
    let state = state();
    let mut header = HeaderPane::new();
    let header_text = render_pane(&mut header, &state, 60, 1);
    assert!(header_text.contains("Miden Debugger"));

    let mut error = ErrorPane::new("execution failed");
    let error_text = render_pane(&mut error, &state, 40, 6);
    assert!(error_text.contains("Program Error"));
    assert!(error_text.contains("execution failed"));
    assert!(error_text.contains("Esc/Enter/q close"));
}

#[test]
fn renders_empty_and_populated_execution_panes() {
    let mut state = state();
    state.executor_mut().current_stack = vec![Felt::from(12345u32), Felt::from(67890u32)];

    let style = Style::default();
    let mut stack = OperandStackPane::new(true, style);
    let stack_text = render_pane(&mut stack, &state, 32, 6);
    assert!(stack_text.contains("Operand Stack"));
    assert!(stack_text.contains("depth is 2"));
    assert!(stack_text.lines().nth(1).unwrap().contains("67890"));
    assert!(stack_text.lines().nth(2).unwrap().contains("12345"));

    state.executor_mut().current_stack.clear();
    let empty_stack_text = render_pane(&mut stack, &state, 32, 6);
    assert!(empty_stack_text.contains("depth is 0"));
    assert!(!empty_stack_text.contains("12345"));
    assert!(!empty_stack_text.contains("67890"));

    let mut disassembly = DisassemblyPane::new(false, style);
    let disassembly_text = render_pane(&mut disassembly, &state, 48, 6);
    assert!(disassembly_text.contains("Disassembly"));
    assert!(disassembly_text.contains("at cycle"));

    let mut stacktrace = StackTracePane::new(false, style);
    let stacktrace_text = render_pane(&mut stacktrace, &state, 48, 6);
    assert!(stacktrace_text.contains("Stack Trace"));

    let mut breakpoints = BreakpointsPane::new(false, style);
    let breakpoints_text = render_pane(&mut breakpoints, &state, 48, 6);
    assert!(breakpoints_text.contains("Breakpoints"));
}

#[test]
fn renders_debug_log_and_footer_modes() {
    let mut state = state();
    let mut debug = DebugPane::default();
    let debug_text = render_pane(&mut debug, &state, 48, 6);
    assert!(debug_text.contains("Debug Log"));

    let mut footer = FooterPane::new();
    let status_text = render_pane(&mut footer, &state, 48, 1);
    assert!(status_text.contains("[N]"));

    footer
        .update(Action::FocusFooter(":".into(), Some("vars".into())), &mut state)
        .expect("footer should enter command mode");
    let command_text = render_pane(&mut footer, &state, 48, 2);
    assert!(command_text.contains("[C]"));
    assert!(command_text.contains(":vars"));
}

#[test]
fn pane_updates_change_focus_state_without_terminal_io() {
    let mut state = state();
    let style = Style::default();

    let mut panes: Vec<Box<dyn Pane>> = vec![
        Box::new(OperandStackPane::new(false, style)),
        Box::new(DisassemblyPane::new(false, style)),
        Box::new(StackTracePane::new(false, style)),
        Box::new(BreakpointsPane::new(false, style)),
    ];
    for pane in &mut panes {
        let unfocused = render_pane(pane.as_mut(), &state, 48, 6);
        assert!(unfocused.starts_with('┌'));

        pane.update(Action::Focus, &mut state).expect("pane should focus");
        let focused = render_pane(pane.as_mut(), &state, 48, 6);
        assert!(focused.starts_with('┏'));
        assert_ne!(focused, unfocused);

        pane.update(Action::UnFocus, &mut state).expect("pane should unfocus");
        assert_eq!(render_pane(pane.as_mut(), &state, 48, 6), unfocused);
    }
}
