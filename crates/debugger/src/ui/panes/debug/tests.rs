use std::{boxed::Box, string::String};

use crossterm::event::{KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::{config::DebuggerConfig, program_loader::test_package_input};

#[test]
fn log_popup_renders_severities_navigates_and_intercepts_keys() {
    let mut state = State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .unwrap();
    let mut pane = DebugPane {
        logger: Box::leak(Box::new(DebugLogger::default())),
        entries: VecDeque::new(),
        selected_entry: None,
    };
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.selected_entry, None);
    for (level, color) in [
        (log::Level::Trace, Color::LightCyan),
        (log::Level::Debug, Color::LightMagenta),
        (log::Level::Info, Color::LightGreen),
        (log::Level::Warn, Color::LightYellow),
        (log::Level::Error, Color::LightRed),
    ] {
        assert_eq!(DebugPane::level_color(level), color);
        pane.entries.push_back(LogEntry {
            level,
            target: "test".into(),
            file: None,
            line: None,
            message: format!("message {level}"),
        });
    }
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.selected_entry, Some(4));
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.selected_entry, Some(0));
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.selected_entry, Some(4));
    for (code, expected) in [
        (KeyCode::Down, Action::Down),
        (KeyCode::Char('j'), Action::Down),
        (KeyCode::Up, Action::Up),
        (KeyCode::Char('K'), Action::Up),
        (KeyCode::Esc, Action::ClosePopup),
        (KeyCode::Char('x'), Action::Noop),
    ] {
        assert!(
            matches!(pane.handle_key_events(KeyEvent::new(code, KeyModifiers::NONE), &mut state).unwrap(), Some(EventResponse::Stop(action)) if action == expected)
        );
    }
    for mode in [InputMode::Insert, InputMode::Command] {
        state.input_mode = mode;
        assert!(matches!(
            pane.handle_key_events(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &mut state)
                .unwrap(),
            Some(EventResponse::Stop(Action::Noop))
        ));
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    terminal.draw(|frame| pane.draw(frame, frame.area(), &state).unwrap()).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("message ERROR"));
    assert!(text.contains("message TRACE"));
    assert!(text.contains("Debug Log"));
}
