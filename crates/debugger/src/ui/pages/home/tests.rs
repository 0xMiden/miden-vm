use std::string::String;

use ratatui::{Terminal, backend::TestBackend, crossterm::event::KeyModifiers};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::*;
use crate::{DebuggerConfig, program_loader::test_package_input, ui::tui::Event};

fn setup() -> (Home, State, UnboundedReceiver<Action>) {
    let state = State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .unwrap();
    let mut home = Home::new().unwrap();
    let (sender, receiver) = unbounded_channel();
    home.register_action_handler(sender).unwrap();
    home.init(&state).unwrap();
    (home, state, receiver)
}

fn draw(home: &mut Home, state: &State) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 80)).unwrap();
    terminal.draw(|frame| home.draw(frame, frame.area(), state).unwrap()).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|row| {
            (0..buffer.area.width)
                .map(|column| buffer[(column, row)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn command(
    home: &mut Home,
    state: &mut State,
    receiver: &mut UnboundedReceiver<Action>,
    text: &str,
) -> Action {
    home.update(Action::FooterResult(":".into(), Some(text.into())), state).unwrap();
    receiver.try_recv().unwrap()
}

#[test]
fn focus_navigation_wraps_and_fullscreen_renders_only_selected_pane() {
    let (mut home, mut state, mut receiver) = setup();
    home.focus().unwrap();
    assert!(
        matches!(receiver.try_recv().unwrap(), Action::StatusLine(message) if message.contains("pane movement"))
    );
    assert_eq!(home.focused_pane_index, 0);
    home.update(Action::FocusPrev, &mut state).unwrap();
    assert_eq!(home.focused_pane_index, 4);
    home.update(Action::FocusNext, &mut state).unwrap();
    assert_eq!(home.focused_pane_index, 0);
    let normal = draw(&mut home, &state);
    assert!(normal.contains("Operand Stack"));
    assert!(normal.contains("Breakpoints"), "{normal}");
    for _ in 0..3 {
        home.update(Action::FocusNext, &mut state).unwrap();
    }
    assert_eq!(home.focused_pane_index, 3);
    home.update(Action::ToggleFullScreen, &mut state).unwrap();
    assert_eq!(home.fullscreen_pane_index, Some(3));
    let fullscreen = draw(&mut home, &state);
    assert!(fullscreen.contains("Operand Stack"));
    assert!(!fullscreen.contains("Breakpoints"));
    home.update(Action::ToggleFullScreen, &mut state).unwrap();
    assert_eq!(home.fullscreen_pane_index, None);
    assert!(draw(&mut home, &state).contains("Breakpoints"));
    home.update(Action::FocusFooter(":".into(), None), &mut state).unwrap();
    home.update(Action::FooterResult(":".into(), None), &mut state).unwrap();
    home.update(Action::Tick, &mut state).unwrap();
    home.update(Action::Update, &mut state).unwrap();
}

#[test]
fn footer_commands_manage_breakpoints_and_report_parse_errors() {
    let (mut home, mut state, mut receiver) = setup();
    assert_eq!(
        command(&mut home, &mut state, &mut receiver, "b at 3"),
        Action::TimedStatusLine("breakpoint created".into(), 1)
    );
    assert_eq!(state.breakpoints.len(), 1);
    assert_eq!(state.breakpoints[0].ty, BreakpointType::StepTo(3));
    assert!(
        matches!(command(&mut home, &mut state, &mut receiver, "b at invalid"), Action::TimedStatusLine(message, 5) if message.contains("invalid breakpoint"))
    );
    assert_eq!(state.breakpoints.len(), 1);
    for text in ["unknown", "unknown argument"] {
        assert_eq!(
            command(&mut home, &mut state, &mut receiver, text),
            Action::TimedStatusLine("unknown command".into(), 1)
        );
    }
    for text in ["vars", "variables all", "locals"] {
        assert!(
            matches!(command(&mut home, &mut state, &mut receiver, text), Action::StatusLine(message) if message.contains("No debug variables tracked"))
        );
    }
    assert_eq!(
        command(&mut home, &mut state, &mut receiver, "where"),
        Action::StatusLine("proc: <unknown>".into())
    );
    assert_eq!(command(&mut home, &mut state, &mut receiver, "debug"), Action::ShowDebug);
    assert_eq!(command(&mut home, &mut state, &mut receiver, "reload"), Action::Reload);
    assert_eq!(command(&mut home, &mut state, &mut receiver, "q"), Action::Quit);
    assert!(matches!(
        command(&mut home, &mut state, &mut receiver, "r invalid"),
        Action::TimedStatusLine(_, 5)
    ));
    assert_eq!(
        command(&mut home, &mut state, &mut receiver, "r 0 -t u32"),
        Action::StatusLine("0".into())
    );
    assert!(
        matches!(command(&mut home, &mut state, &mut receiver, "r 0 -c 2"), Action::TimedStatusLine(message, 5) if message.contains("not yet implemented"))
    );
}

#[test]
fn key_events_dispatch_navigation_and_respect_input_mode() {
    let (mut home, mut state, _receiver) = setup();
    for (key, action) in [
        (KeyCode::Right, Action::FocusNext),
        (KeyCode::Left, Action::FocusPrev),
        (KeyCode::Down, Action::Down),
        (KeyCode::Up, Action::Up),
        (KeyCode::Char('g'), Action::Go),
        (KeyCode::Backspace, Action::Back),
        (KeyCode::Char('f'), Action::ToggleFullScreen),
        (KeyCode::Char('2'), Action::Tab(1)),
        (KeyCode::Char(']'), Action::TabNext),
        (KeyCode::Char('['), Action::TabPrev),
        (KeyCode::Char(':'), Action::FocusFooter(":".into(), None)),
        (KeyCode::Char('q'), Action::Quit),
        (KeyCode::Char('d'), Action::Delete),
    ] {
        let response = home
            .handle_events(Event::Key(KeyEvent::new(key, KeyModifiers::NONE)), &mut state)
            .unwrap();
        assert!(matches!(response, Some(EventResponse::Stop(actual)) if actual == action));
    }
    assert!(home.handle_events(Event::Tick, &mut state).unwrap().is_none());
    assert!(
        home.handle_key_events(KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE), &mut state)
            .unwrap()
            .is_none()
    );
    for mode in [InputMode::Insert, InputMode::Command] {
        state.input_mode = mode;
        assert!(
            home.handle_key_events(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
                &mut state
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn execution_keys_step_continue_and_reject_completed_programs() {
    for key in ['s', 'n', 'c', 'e'] {
        let (mut home, mut state, mut receiver) = setup();
        let response = home
            .handle_key_events(KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE), &mut state)
            .unwrap();
        assert!(matches!(response, Some(EventResponse::Stop(Action::Continue))));
        assert!(!state.stopped);
        home.update(Action::Continue, &mut state).unwrap();
        assert!(state.executor().cycle > 0);
        home.update(Action::Reload, &mut state).unwrap();
        assert_eq!(state.executor().cycle, 0);
        while receiver.try_recv().is_ok() {}
    }
    let (mut home, mut state, mut receiver) = setup();
    assert_eq!(command(&mut home, &mut state, &mut receiver, "nl"), Action::Continue);
    home.update(Action::Continue, &mut state).unwrap();
    state.breakpoints.clear();
    home.update(Action::Continue, &mut state).unwrap();
    assert!(state.executor().stopped);
    while receiver.try_recv().is_ok() {}
    for key in ['s', 'n', 'c'] {
        let response = home
            .handle_key_events(KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE), &mut state)
            .unwrap();
        assert!(
            matches!(response, Some(EventResponse::Stop(Action::TimedStatusLine(message, 3))) if message.contains("terminated"))
        );
    }
    assert!(
        matches!(command(&mut home, &mut state, &mut receiver, "nl"), Action::TimedStatusLine(message, 3) if message.contains("terminated"))
    );
}
