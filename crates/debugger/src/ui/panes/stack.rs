use std::vec::Vec;

use miden_assembly_syntax::diagnostics::Report;
use ratatui::{prelude::*, widgets::*};

use crate::ui::{action::Action, panes::Pane, state::State, tui::Frame};

pub struct OperandStackPane {
    focused: bool,
    focused_border_style: Style,
}

impl OperandStackPane {
    pub fn new(focused: bool, focused_border_style: Style) -> Self {
        Self {
            focused,
            focused_border_style,
        }
    }

    fn border_style(&self) -> Style {
        match self.focused {
            true => self.focused_border_style,
            false => Style::default(),
        }
    }

    fn border_type(&self) -> BorderType {
        match self.focused {
            true => BorderType::Thick,
            false => BorderType::Plain,
        }
    }
}

impl Pane for OperandStackPane {
    fn height_constraint(&self) -> Constraint {
        match self.focused {
            true => Constraint::Max(30),
            false => Constraint::Max(30),
        }
    }

    fn update(&mut self, action: Action, _state: &mut State) -> Result<Option<Action>, Report> {
        match action {
            Action::Focus => {
                self.focused = true;
            }
            Action::UnFocus => {
                self.focused = false;
            }
            _ => {}
        }

        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame<'_>, area: Rect, state: &State) -> Result<(), Report> {
        let lines: Vec<Line<'_>> = if state.executor().current_stack.is_empty() {
            vec![]
        } else {
            state
                .executor()
                .current_stack
                .iter()
                .rev()
                .map(|item| {
                    Line::from(Span::styled(format!(" {}", item.as_canonical_u64()), Color::Gray))
                })
                .collect()
        };

        let depth = lines.len();
        let selected_line = depth.saturating_sub(1);
        let list = List::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .highlight_symbol(symbols::scrollbar::HORIZONTAL.end)
            .highlight_spacing(HighlightSpacing::Always)
            .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
        let mut list_state = ListState::default().with_selected(Some(selected_line));

        frame.render_stateful_widget(list, area, &mut list_state);
        frame.render_widget(
            Block::default()
                .title("Operand Stack")
                .borders(Borders::ALL)
                .border_style(self.border_style())
                .border_type(self.border_type())
                .title_bottom(
                    Line::styled(
                        format!("depth is {depth}"),
                        Style::default().add_modifier(Modifier::ITALIC),
                    )
                    .right_aligned(),
                ),
            area,
        );
        Ok(())
    }
}
