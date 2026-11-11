use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::{program_loader::test_package_input, ui::action::Action};

#[test]
fn application_renders_execution_and_popups_without_a_real_terminal() {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut app = runtime
        .block_on(App::new(Box::new(DebuggerConfig {
            input: Some(test_package_input()),
            ..Default::default()
        })))
        .unwrap();
    assert_eq!(app.active_page, 0);
    assert_eq!(app.mode, Mode::Home);
    assert!(!app.should_quit);
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    for popup in [
        None,
        Some(Box::new(ErrorPane::new("test failure")) as Box<dyn Pane>),
        Some(Box::new(DebugPane::default()) as Box<dyn Pane>),
    ] {
        let has_popup = popup.is_some();
        app.popup = popup;
        app.footer.update(Action::StatusLine("ready".into()), &mut app.state).unwrap();
        terminal.draw(|frame| app.draw(frame).unwrap()).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<std::string::String>();
        assert!(text.contains("ready"));
        assert!(text.contains("Operand Stack"));
        if !has_popup {
            assert!(text.contains("Breakpoints"));
        } else {
            assert!(text.contains("Program Error") || text.contains("Debug Log"));
        }
    }
    app.active_page = 10;
    app.popup = None;
    terminal.draw(|frame| app.draw(frame).unwrap()).unwrap();
}
