use std::{
    boxed::Box,
    collections::BTreeMap,
    ops::Deref,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    debuginfo::{SourceFile, SourceId, SourceSpan},
    diagnostics::{Report, SourceCode},
};
use ratatui::{prelude::*, widgets::*};

use crate::{
    debug::ResolvedLocation,
    ui::{
        action::Action,
        panes::Pane,
        state::State,
        syntax_highlighting::{
            Highlighter, HighlighterState, NoopHighlighter, SyntectHighlighter,
            clamp_byte_selection_to_str,
        },
        tui::Frame,
    },
};

pub struct SourceCodePane {
    focused: bool,
    current_source_id: SourceId,
    current_span: SourceSpan,
    current_line: u32,
    current_col: u32,
    num_lines: u32,
    selected_line: u32,
    last_selected_stack_frame: usize,
    syntax_highlighter: Box<dyn Highlighter>,
    syntax_highlighting_states: BTreeMap<SourceId, Box<dyn HighlighterState>>,
    current_file: Option<HighlightedFile>,
    theme: Theme,
}

struct HighlightedFile {
    source_file: Arc<SourceFile>,
    /// The syntax highlighted lines of `source_file`, cached so that patching
    /// them with the current selected line can be done efficiently
    lines: Vec<Vec<Span<'static>>>,
    selected_span: SourceSpan,
    gutter_width: u8,
}

impl SourceCodePane {
    fn highlight_file(&mut self, resolved: &ResolvedLocation) -> HighlightedFile {
        let highlighter_state = self
            .syntax_highlighting_states
            .entry(resolved.source_file.id())
            .or_insert_with(|| {
                let span_contents = resolved
                    .source_file
                    .read_span(&resolved.source_file.source_span().into(), 0, 0)
                    .expect("failed to read span of file");
                self.syntax_highlighter.start_highlighter_state(span_contents.as_ref())
            });
        let resolved_span = resolved.span.into_slice_index();
        let content = resolved.source_file.content();
        let last_line = content.last_line_index();
        let max_line_no = last_line.number().to_usize();
        let gutter_width = max_line_no.ilog10() as u8;
        let lines = (0..max_line_no)
            .map(|line_index| {
                let line_index = miden_debug_types::LineIndex::from(line_index as u32);
                let span = content.line_range(line_index).expect("invalid line index");
                let span = span.start.to_usize()..span.end.to_usize();

                // Only highlight a portion of the line if the full span fits on that line
                let is_highlighted = span.contains(&resolved_span.start)
                    && span.contains(&resolved_span.end)
                    && span != resolved_span;

                let line_content =
                    strip_newline(&content.as_bytes()[span.start..span.end]).into_owned();
                if is_highlighted {
                    let selection = if resolved.span.is_empty() {
                        // Select the closest character to the span
                        //let start = core::cmp::max(span.start, resolved_span.start);
                        //let end = core::cmp::min(span.end, resolved_span.end.saturating_add(1));
                        //(start - span.start)..(end - span.start)
                        0..(span.end - span.start)
                    } else {
                        (resolved_span.start - span.start)..(resolved_span.end - span.start)
                    };
                    let selection = clamp_byte_selection_to_str(&line_content, selection);
                    highlighter_state.highlight_line_with_selection(
                        line_content.into(),
                        selection,
                        self.theme.current_span,
                    )
                } else {
                    highlighter_state.highlight_line(line_content.into())
                }
            })
            .collect::<Vec<_>>();

        HighlightedFile {
            source_file: resolved.source_file.clone(),
            lines,
            selected_span: resolved.span,
            gutter_width,
        }
    }

    fn clear_location(&mut self) {
        self.current_source_id = SourceId::UNKNOWN;
        self.current_span = SourceSpan::default();
        self.current_line = 0;
        self.current_col = 0;
        self.num_lines = 0;
        self.selected_line = 0;
        self.current_file = None;
    }

    fn update_location(&mut self, location: Option<ResolvedLocation>, selected_stack_frame: usize) {
        match location {
            Some(loc) => {
                let source_id = loc.source_file.id();
                if source_id != self.current_source_id {
                    self.current_file = Some(self.highlight_file(&loc));
                    self.current_source_id = source_id;
                    self.num_lines = loc.source_file.line_count() as u32;
                    self.selected_line = loc.line;
                } else if self.selected_line != loc.line {
                    self.selected_line = loc.line;
                }
                if let Some(current_file) = self.current_file.as_mut() {
                    current_file.selected_span = loc.span;
                }
                self.current_span = loc.span;
                self.current_line = loc.line;
                self.current_col = loc.col;
            }
            None if selected_stack_frame != self.last_selected_stack_frame => {
                self.clear_location();
            }
            None => {}
        }
        self.last_selected_stack_frame = selected_stack_frame;
    }
}

struct Theme {
    focused_border_style: Style,
    current_line: Style,
    current_span: Style,
    line_number: Style,
    #[allow(dead_code)]
    gutter_border: Style,
}
impl Default for Theme {
    fn default() -> Self {
        Self {
            focused_border_style: Style::default(),
            current_line: Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            current_span: Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            line_number: Style::default(),
            gutter_border: Style::default(),
        }
    }
}
impl Theme {
    pub fn patch_from_syntect(&mut self, _theme: &syntect::highlighting::Theme) {
        // Intentionally do NOT apply the syntect theme's line_highlight, selection,
        // or gutter colors here. The defaults use REVERSED which works on both
        // light and dark terminals. The syntect dark theme colors would make text
        // invisible on light terminals.
    }
}

impl SourceCodePane {
    pub fn new(focused: bool, focused_border_style: Style) -> Self {
        let theme = Theme {
            focused_border_style,
            ..Default::default()
        };
        Self {
            focused,
            current_source_id: SourceId::UNKNOWN,
            num_lines: 0,
            selected_line: 0,
            last_selected_stack_frame: 0,
            current_line: 0,
            current_col: 0,
            current_span: SourceSpan::default(),
            syntax_highlighter: Box::new(NoopHighlighter),
            syntax_highlighting_states: Default::default(),
            current_file: None,
            theme,
        }
    }

    fn reload(&mut self, state: &State) {
        self.clear_location();
        self.update_location(state.selected_display_location(), state.selected_stack_frame());
    }

    fn border_style(&self) -> Style {
        match self.focused {
            true => self.theme.focused_border_style,
            false => Style::default(),
        }
    }

    fn border_type(&self) -> BorderType {
        match self.focused {
            true => BorderType::Thick,
            false => BorderType::Plain,
        }
    }

    fn enable_syntax_highlighting(&mut self, state: &State) {
        let nocolor = !state.config.color.should_attempt_color();
        if nocolor {
            return;
        }

        let syntax_set = syntect::parsing::SyntaxSet::load_defaults_nonewlines();
        let theme_set = syntect::highlighting::ThemeSet::load_defaults();
        let theme = theme_set.themes["base16-eighties.dark"].clone();
        self.theme.patch_from_syntect(&theme);
        self.syntax_highlighter = Box::new(SyntectHighlighter::new(syntax_set, theme, false));
    }
}

impl Pane for SourceCodePane {
    fn init(&mut self, state: &State) -> Result<(), Report> {
        self.enable_syntax_highlighting(state);
        self.update_location(state.selected_display_location(), state.selected_stack_frame());

        Ok(())
    }

    fn height_constraint(&self) -> Constraint {
        match self.focused {
            true => Constraint::Fill(3),
            false => Constraint::Fill(3),
        }
    }

    fn update(&mut self, action: Action, state: &mut State) -> Result<Option<Action>, Report> {
        match action {
            Action::Down => {
                if self.num_lines > 0 {
                    self.selected_line =
                        core::cmp::min(self.selected_line.saturating_add(1), self.num_lines);
                }
                return Ok(Some(Action::Update));
            }
            Action::Up => {
                if self.num_lines > 0 {
                    self.selected_line =
                        core::cmp::min(self.selected_line.saturating_sub(1), self.num_lines);
                }
                return Ok(Some(Action::Update));
            }
            Action::Focus => {
                self.focused = true;
                static STATUS_LINE: &str = "[j,k → movement]";
                return Ok(Some(Action::TimedStatusLine(STATUS_LINE.into(), 3)));
            }
            Action::UnFocus => {
                self.focused = false;
            }
            Action::Submit => {}
            Action::Update => {
                self.update_location(
                    state.selected_display_location(),
                    state.selected_stack_frame(),
                );
            }
            Action::Reload => {
                self.reload(state);
            }
            _ => {}
        }

        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame<'_>, area: Rect, _state: &State) -> Result<(), Report> {
        let current_file = self.current_file.as_ref();
        if current_file.is_none() {
            frame.render_widget(
                Block::default()
                    .title("Source Code")
                    .borders(Borders::ALL)
                    .border_style(self.border_style())
                    .border_type(self.border_type())
                    .title_bottom(
                        Line::from("no source code available for current instruction")
                            .right_aligned(),
                    )
                    .title(
                        Line::styled("nofile", Style::default().add_modifier(Modifier::ITALIC))
                            .right_aligned(),
                    ),
                area,
            );
            return Ok(());
        }

        let current_file = unsafe { current_file.unwrap_unchecked() };

        // Get the cached (highlighted) lines for the current source file
        let mut lines = current_file.lines.clone();
        if lines.is_empty() {
            return Ok(());
        }
        // Extract the current selected line as a vector of raw syntect parts,
        // clamping to the file in case debug info points past the last line
        let selected_line = (self.selected_line.saturating_sub(1) as usize).min(lines.len() - 1);
        let selected_line_deconstructed = lines[selected_line]
            .iter()
            .map(|span| {
                (
                    crate::ui::syntax_highlighting::convert_to_syntect_style(span.style, false),
                    span.content.as_ref(),
                )
            })
            .collect::<Vec<_>>();

        // Modify the selected line's highlighting style to reflect the selection
        let syntect_style = syntect::highlighting::StyleModifier {
            foreground: self
                .theme
                .current_span
                .fg
                .map(crate::ui::syntax_highlighting::convert_to_syntect_color),
            background: self
                .theme
                .current_span
                .bg
                .map(crate::ui::syntax_highlighting::convert_to_syntect_color),
            font_style: if self.theme.current_span.add_modifier.is_empty() {
                None
            } else {
                Some(crate::ui::syntax_highlighting::convert_to_font_style(
                    self.theme.current_span.add_modifier,
                ))
            },
        };
        let span = current_file.selected_span;
        let line_span = current_file
            .source_file
            .content()
            .line_range((selected_line as u32).into())
            .unwrap();
        let selection_start = core::cmp::max(span.start(), line_span.start);
        let selection_end = core::cmp::min(span.end(), line_span.end);
        // Guard: if the span doesn't overlap this line, select nothing
        let selected = if selection_start >= selection_end {
            0..0
        } else {
            let selected_span = SourceSpan::new(span.source_id(), selection_start..selection_end);
            let selected = selected_span.into_slice_index();
            if selected_span.is_empty() {
                let start = selected.start - line_span.start.to_usize();
                start..start
            } else {
                (selected.start - line_span.start.to_usize())
                    ..(selected.end - line_span.start.to_usize())
            }
        };
        let selected_line_content = selected_line_deconstructed
            .iter()
            .map(|(_, content)| *content)
            .collect::<String>();
        let selected = clamp_byte_selection_to_str(&selected_line_content, selected);
        let mut parts = syntect::util::modify_range(
            selected_line_deconstructed.as_slice(),
            selected,
            syntect_style,
        )
        .into_iter()
        .map(|(style, str)| {
            Span::styled(
                str.to_string(),
                crate::ui::syntax_highlighting::convert_style(style, true),
            )
        })
        .collect();
        lines[selected_line].clear();
        lines[selected_line].append(&mut parts);

        let gutter_width = self.current_file.as_ref().unwrap().gutter_width as usize;
        let lines = lines.into_iter().enumerate().map(|(line_index, highlighted_parts)| {
            let line_number_style = if line_index == selected_line {
                self.theme.current_line
            } else {
                self.theme.line_number
            };
            Line::from_iter(
                [
                    Span::styled(
                        format!("{line_no:gutter_width$}", line_no = line_index + 1),
                        line_number_style,
                    ),
                    Span::styled(" | ", line_number_style),
                ]
                .into_iter()
                .chain(highlighted_parts),
            )
        });

        // Render the syntax-highlighted lines
        let list = List::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .highlight_symbol(symbols::scrollbar::HORIZONTAL.end)
            .highlight_spacing(HighlightSpacing::Always)
            .scroll_padding(15);
        let mut list_state = ListState::default().with_selected(Some(selected_line));

        frame.render_stateful_widget(list, area, &mut list_state);
        frame.render_widget(
            Block::default()
                .title("Source Code")
                .borders(Borders::ALL)
                .border_style(self.border_style())
                .border_type(self.border_type())
                .title_bottom(
                    Line::from(format!("{} of {}", self.selected_line, self.num_lines,))
                        .right_aligned(),
                )
                .title(
                    Line::styled(
                        current_file.source_file.deref().uri().as_str(),
                        Style::default().add_modifier(Modifier::ITALIC),
                    )
                    .right_aligned(),
                ),
            area,
        );
        Ok(())
    }
}

fn strip_newline(s: &[u8]) -> std::borrow::Cow<'_, str> {
    if let Some(sans_newline) = s.strip_suffix(b"\n") {
        String::from_utf8_lossy(sans_newline)
    } else {
        String::from_utf8_lossy(s)
    }
}

#[cfg(test)]
mod tests;
