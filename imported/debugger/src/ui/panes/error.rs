use std::string::String;

use crossterm::event::KeyCode;
use miden_assembly_syntax::diagnostics::Report;
use ratatui::{prelude::*, widgets::*};

use crate::ui::{
    action::Action,
    panes::Pane,
    state::State,
    tui::{EventResponse, Frame},
};

pub struct ErrorPane {
    message: String,
}

impl ErrorPane {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Pane for ErrorPane {
    fn height_constraint(&self) -> Constraint {
        Constraint::Percentage(40)
    }

    fn handle_key_events(
        &mut self,
        key: crossterm::event::KeyEvent,
        _state: &mut State,
    ) -> Result<Option<EventResponse<Action>>, Report> {
        let action = match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::ClosePopup,
            _ => Action::Noop,
        };
        Ok(Some(EventResponse::Stop(action)))
    }

    fn draw(&mut self, frame: &mut Frame<'_>, area: Rect, _state: &State) -> Result<(), Report> {
        frame.render_widget(Clear, area);

        let block = Block::default()
            .title("Program Error")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::LightRed))
            .title_style(Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let message = Paragraph::new(self.message.as_str())
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: false });
        frame.render_widget(message, inner);

        let footer = Line::from("Esc/Enter/q close")
            .right_aligned()
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(footer, area);

        Ok(())
    }
}
