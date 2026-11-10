use std::{boxed::Box, time::Duration};

use ratatui::{Terminal, backend::TestBackend, crossterm::event::KeyModifiers};

use super::*;
use crate::{config::DebuggerConfig, program_loader::test_package_input};

fn state() -> State {
    State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .unwrap()
}

#[test]
fn command_history_navigation_wraps_and_submission_and_cancel_restore_mode() {
    let mut state = state();
    let mut pane = FooterPane::new();
    assert_eq!(pane.height_constraint(), Constraint::Max(1));
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    assert!(pane.handle_key_events(key(KeyCode::Enter), &mut state).unwrap().is_none());
    for command in ["first", "second"] {
        assert_eq!(
            pane.update(Action::FocusFooter(":break ".into(), Some(command.into())), &mut state)
                .unwrap(),
            Some(Action::Update)
        );
        assert!(pane.focused);
        assert_eq!(state.input_mode, InputMode::Command);
        assert!(
            matches!(pane.handle_key_events(key(KeyCode::Enter), &mut state).unwrap(), Some(EventResponse::Stop(Action::FooterResult(_, Some(value)))) if value == command)
        );
        pane.update(Action::FooterResult(":break ".into(), None), &mut state).unwrap();
        assert!(!pane.focused);
        assert_eq!(state.input_mode, InputMode::Normal);
    }
    pane.update(Action::FocusFooter(":break ".into(), None), &mut state).unwrap();
    for (code, expected) in [
        (KeyCode::Up, "second"),
        (KeyCode::Up, "first"),
        (KeyCode::Up, "second"),
        (KeyCode::Down, "first"),
    ] {
        assert!(pane.handle_key_events(key(code), &mut state).unwrap().is_none());
        assert_eq!(pane.input.value(), expected);
    }
    assert!(matches!(
        pane.handle_key_events(key(KeyCode::Esc), &mut state).unwrap(),
        Some(EventResponse::Stop(Action::FooterResult(_, None)))
    ));
    assert_eq!(pane.command_history_index, None);
    pane.handle_key_events(key(KeyCode::Down), &mut state).unwrap();
    assert_eq!(pane.input.value(), "first");
    pane.update(Action::FocusFooter(":break ".into(), None), &mut state).unwrap();
    pane.handle_key_events(key(KeyCode::Enter), &mut state).unwrap();
    assert_eq!(pane.command_history.len(), 2);
    for index in 0..25 {
        pane.input = Input::new(index.to_string());
        pane.handle_key_events(key(KeyCode::Enter), &mut state).unwrap();
    }
    assert_eq!(pane.command_history.len(), 20);
    assert_eq!(pane.command_history.back().unwrap(), "5");
}

#[test]
fn footer_renders_input_modes_and_expires_temporary_status() {
    let mut state = state();
    let mut pane = FooterPane::new();
    pane.update(Action::StatusLine("ready".into()), &mut state).unwrap();
    pane.update(Action::TimedStatusLine("temporary".into(), 10), &mut state)
        .unwrap();
    assert_eq!(pane.get_status_line(), "temporary");
    pane.timed_status_line.as_mut().unwrap().created = Instant::now() - Duration::from_secs(11);
    assert_eq!(pane.get_status_line(), "ready");
    assert!(pane.timed_status_line.is_none());
    let mut terminal = Terminal::new(TestBackend::new(60, 2)).unwrap();
    for (mode, label) in [(InputMode::Normal, "[N]"), (InputMode::Insert, "[I]")] {
        state.input_mode = mode;
        terminal
            .draw(|frame| pane.draw(frame, Rect::new(0, 0, 60, 1), &state).unwrap())
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("ready"));
        assert!(text.contains(label));
    }
    pane.update(Action::FocusFooter(":break ".into(), Some("main".into())), &mut state)
        .unwrap();
    terminal
        .draw(|frame| pane.draw(frame, Rect::new(0, 0, 60, 1), &state).unwrap())
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains(":break main"));
    assert!(text.contains("[C]"));
    assert!(pane.update(Action::Noop, &mut state).unwrap().is_none());
}
