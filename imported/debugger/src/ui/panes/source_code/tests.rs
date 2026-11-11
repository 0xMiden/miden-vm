use std::{fs, path::PathBuf};

use miden_assembly::DefaultSourceManager;
use miden_debug_types::{ByteIndex, SourceManagerExt};

use super::*;

#[test]
fn rendering_source_preserves_text_selection_focus_and_navigation() {
    use ratatui::{Terminal, backend::TestBackend};

    use crate::{
        config::{ColorChoice, DebuggerConfig},
        program_loader::test_package_input,
    };

    let mut state = State::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        color: ColorChoice::Always,
        ..Default::default()
    }))
    .unwrap();
    let (location, path) = test_location("render-navigation");
    let mut pane = SourceCodePane::new(false, Style::new().fg(Color::Blue));
    pane.init(&state).unwrap();
    pane.update_location(Some(location.clone()), 0);
    assert_eq!(pane.current_span, location.span);
    assert_eq!(pane.height_constraint(), Constraint::Fill(3));
    let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
    terminal.draw(|frame| pane.draw(frame, frame.area(), &state).unwrap()).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("line one"));
    assert!(text.contains("line two"));
    assert!(text.contains(&format!("1 of {}", pane.num_lines)));
    assert!(
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .any(|cell| cell.modifier.contains(Modifier::REVERSED))
    );
    for _ in 0..pane.num_lines {
        pane.update(Action::Down, &mut state).unwrap();
    }
    assert_eq!(pane.selected_line, pane.num_lines);
    pane.update(Action::Down, &mut state).unwrap();
    assert_eq!(pane.selected_line, pane.num_lines);
    pane.update(Action::Up, &mut state).unwrap();
    assert_eq!(pane.selected_line, pane.num_lines - 1);
    assert!(matches!(
        pane.update(Action::Focus, &mut state).unwrap(),
        Some(Action::TimedStatusLine(_, 3))
    ));
    assert_eq!(pane.border_type(), BorderType::Thick);
    assert_eq!(pane.border_style(), Style::new().fg(Color::Blue));
    pane.update(Action::UnFocus, &mut state).unwrap();
    assert_eq!(pane.border_type(), BorderType::Plain);
    let mut next = location;
    next.line = 2;
    next.col = 1;
    next.span = SourceSpan::new(next.source_file.id(), ByteIndex::new(9)..ByteIndex::new(13));
    pane.update_location(Some(next), 0);
    assert_eq!(pane.selected_line, 2);
    terminal.draw(|frame| pane.draw(frame, frame.area(), &state).unwrap()).unwrap();
    pane.update(Action::Submit, &mut state).unwrap();
    pane.update(Action::Reload, &mut state).unwrap();
    assert!(pane.current_file.is_none());
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn clears_cached_source_when_selection_becomes_unresolvable() {
    let (location, path) = test_location("clear-unresolvable");
    let mut pane = SourceCodePane::new(false, Style::default());
    pane.update_location(Some(location), 0);
    assert!(pane.current_file.is_some());

    pane.update_location(None, 1);

    assert!(pane.current_file.is_none());
    assert!(pane.current_source_id.is_unknown());
    assert_eq!(pane.current_line, 0);
    fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn retains_cached_source_for_unresolved_instruction_in_same_frame() {
    let (location, path) = test_location("retain-transient");
    let mut pane = SourceCodePane::new(false, Style::default());
    pane.update_location(Some(location), 0);

    pane.update_location(None, 0);

    assert!(pane.current_file.is_some());
    assert!(!pane.current_source_id.is_unknown());
    assert_eq!(pane.current_line, 1);
    fs::remove_dir_all(path.parent().unwrap()).ok();
}

fn test_location(test_name: &str) -> (ResolvedLocation, PathBuf) {
    let path = PathBuf::from("target")
        .join("source-pane-tests")
        .join(format!("{test_name}-{}", std::process::id()))
        .join("source.masm");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "line one\nline two\n").unwrap();

    let source_manager = DefaultSourceManager::default();
    let source_file = source_manager.load_file(&path).expect("source should load");
    let span = SourceSpan::new(source_file.id(), ByteIndex::new(0)..ByteIndex::new(4));
    (
        ResolvedLocation {
            source_file,
            line: 1,
            col: 1,
            span,
        },
        path,
    )
}
