use std::{boxed::Box, string::String};

use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::{config::DebuggerConfig, program_loader::test_package_input};

#[test]
fn navigation_wraps_deletion_selects_the_next_breakpoint_and_reload_clears_hits() {
    let mut state = State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .unwrap();
    let mut pane = BreakpointsPane::new(false, Style::new().fg(Color::Blue));
    pane.init(&state).unwrap();
    assert_eq!(pane.height_constraint(), Constraint::Fill(5));
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, None);
    for breakpoint in ["at 10", "after 20", "in entrypoint", "for add", "main.masm:4", "main.masm"]
    {
        state.create_breakpoint(breakpoint.parse().unwrap());
    }
    let first = state.breakpoints[0].id;
    let last = state.breakpoints.last().unwrap().id;
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, Some(last));
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, Some(first));
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, Some(last));
    pane.update(Action::Delete, &mut state).unwrap();
    assert!(!state.breakpoints.iter().any(|breakpoint| breakpoint.id == last));
    assert_eq!(pane.breakpoint_selected, Some(first));
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, Some(state.breakpoints[1].id));
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.breakpoint_selected, Some(first));
    state.breakpoints_hit.push(state.breakpoints[0].clone());
    state.executor_mut().cycle += 1;
    pane.update(Action::Update, &mut state).unwrap();
    assert_eq!(pane.breakpoints_hit.len(), 1);
    assert!(state.breakpoints_hit.is_empty());
    assert_eq!(pane.breakpoint_selected, None);
    let mut terminal = Terminal::new(TestBackend::new(80, 15)).unwrap();
    for action in [Action::Focus, Action::UnFocus] {
        pane.update(action, &mut state).unwrap();
        terminal.draw(|frame| pane.draw(frame, frame.area(), &state).unwrap()).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("Breakpoints"));
        assert!(text.contains("cycle:10"));
        assert!(text.contains("opcode:add"));
        assert!(text.contains("proc:"));
        assert!(text.contains("file:"));
        assert!(text.contains("1 of 5 hit this cycle"));
    }
    pane.update(Action::Reload, &mut state).unwrap();
    assert!(pane.breakpoints_hit.is_empty());
    assert_eq!(pane.breakpoint_selected, None);
    pane.update(Action::Delete, &mut state).unwrap();
    assert_eq!(state.breakpoints.len(), 5);
}
