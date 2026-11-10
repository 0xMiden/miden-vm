use miden_assembly_syntax::diagnostics::Report;
use ratatui::prelude::*;

use crate::ui::{panes::Pane, state::State, tui::Frame};

#[derive(Default)]
pub struct HeaderPane;

impl HeaderPane {
    pub const fn new() -> Self {
        Self
    }
}

impl Pane for HeaderPane {
    fn height_constraint(&self) -> Constraint {
        Constraint::Max(1)
    }

    fn draw(&mut self, frame: &mut Frame<'_>, area: Rect, _state: &State) -> Result<(), Report> {
        frame.render_widget(
            Line::from(vec![
                Span::styled(
                    format!("[ Miden Debugger {} ", symbols::DOT),
                    Style::default().fg(Color::Blue),
                ),
                Span::styled(env!("CARGO_PKG_VERSION"), Style::default().fg(Color::LightCyan)),
                Span::styled("]", Style::default().fg(Color::Blue)),
            ])
            .right_aligned(),
            area,
        );

        Ok(())
    }
}
