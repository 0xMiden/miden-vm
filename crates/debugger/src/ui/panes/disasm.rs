use std::{string::ToString, vec::Vec};

use miden_assembly_syntax::diagnostics::Report;
use ratatui::{prelude::*, widgets::*};

use crate::ui::{action::Action, panes::Pane, state::State, tui::Frame};

pub struct DisassemblyPane {
    focused: bool,
    focused_border_style: Style,
}

impl DisassemblyPane {
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

impl Pane for DisassemblyPane {
    fn height_constraint(&self) -> Constraint {
        match self.focused {
            true => Constraint::Max(7),
            false => Constraint::Max(7),
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
        // Prefer the live AsmOp's context_name — the frame's procedure is sticky
        // (set once on frame entry) so for programs that use `exec` instead of
        // `call` the entire run appears to stay in the first seen procedure.
        let live_proc_name =
            state.executor().current_asmop.as_ref().map(|op| op.context_name().to_string());

        let (current_proc, lines) = match state.executor().callstack.current_frame() {
            None => {
                let proc = Line::from(
                    live_proc_name
                        .as_deref()
                        .map(|p| format!("in {p}"))
                        .unwrap_or_else(|| "in <unknown>".to_string()),
                )
                .right_aligned();
                (
                    proc,
                    state
                        .executor()
                        .recent
                        .iter()
                        .map(|op| Line::from(vec![Span::styled(format!(" | {op}"), Color::Gray)]))
                        .collect::<Vec<_>>(),
                )
            }
            Some(frame) => {
                let proc_name =
                    live_proc_name.clone().or_else(|| frame.procedure("").map(|p| p.to_string()));
                let proc = proc_name
                    .map(|p| Line::from(format!("in {p}")))
                    .unwrap_or_else(|| Line::from("in <unknown>"))
                    .right_aligned();
                (
                    proc,
                    frame
                        .recent()
                        .iter()
                        .map(|op| {
                            Line::from(vec![Span::styled(
                                format!(" | {}", op.display()),
                                Color::Gray,
                            )])
                        })
                        .collect::<Vec<_>>(),
                )
            }
        };
        let selected_line = lines.len().saturating_sub(1);

        let list = List::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .highlight_symbol(symbols::scrollbar::HORIZONTAL.end)
            .highlight_spacing(HighlightSpacing::Always)
            .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
        let mut list_state = ListState::default().with_selected(Some(selected_line));

        frame.render_stateful_widget(list, area, &mut list_state);
        frame.render_widget(
            Block::default()
                .title("Disassembly")
                .borders(Borders::ALL)
                .border_style(self.border_style())
                .border_type(self.border_type())
                .title_bottom(current_proc)
                .title(
                    Line::styled(
                        format!(" at cycle {}", state.executor().cycle),
                        Style::default().add_modifier(Modifier::ITALIC),
                    )
                    .right_aligned(),
                ),
            area,
        );
        Ok(())
    }
}
