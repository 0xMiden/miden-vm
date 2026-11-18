//! Plain-text rendering for library reports and command-line tools.

use core::fmt::{self, Write};

use miden_debug_types::{ByteIndex, SourceFile};
use unicode_width::UnicodeWidthChar;

use crate::{Diagnostic, Label};

/// Renders a diagnostic via [fmt::Display].
pub struct PrintDiagnostic<D>(D);

impl<D: AsRef<dyn Diagnostic>> PrintDiagnostic<D> {
    pub fn new(diagnostic: D) -> Self {
        Self(diagnostic)
    }

    pub fn new_without_color(diagnostic: D) -> Self {
        Self::new(diagnostic)
    }
}

impl<D: AsRef<dyn Diagnostic>> fmt::Display for PrintDiagnostic<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        render(f, self.0.as_ref())
    }
}

pub(crate) fn render(out: &mut impl Write, diagnostic: &dyn Diagnostic) -> fmt::Result {
    render_diagnostic(&mut PlainText(out), diagnostic, None, 0)
}

// Keep line breaks in diagnostic prose while escaping terminal controls from every field.
struct PlainText<'a, W>(&'a mut W);

impl<W: Write> Write for PlainText<'_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut start = 0;
        for (index, ch) in text.char_indices().filter(|&(_, ch)| ch != '\n' && ch.is_control()) {
            self.0.write_str(&text[start..index])?;
            for escaped in ch.escape_debug() {
                self.0.write_char(escaped)?;
            }
            start = index + ch.len_utf8();
        }
        self.0.write_str(&text[start..])
    }
}

fn render_diagnostic(
    out: &mut impl Write,
    diagnostic: &dyn Diagnostic,
    inherited_source: Option<&SourceFile>,
    depth: usize,
) -> fmt::Result {
    const MAX_DEPTH: usize = 32;
    if depth == MAX_DEPTH {
        return writeln!(out, "  ...");
    }

    let details = diagnostic.details();
    write!(out, "{}", diagnostic.severity())?;
    if let Some(code) = details.code {
        write!(out, "[{code}]")?;
    }
    writeln!(out, ": {diagnostic}")?;

    let mut cause = diagnostic.source();
    for _ in depth..MAX_DEPTH {
        let Some(error) = cause else { break };
        writeln!(out, "  caused by: {error}")?;
        cause = error.source();
    }

    let source = details.source.or(inherited_source);
    let has_primary_label = details.labels.iter().any(|label| label.primary);
    for label in details.labels.iter() {
        if let Some(source) = source.filter(|_| !label.span.is_synthetic()) {
            match Excerpt::new(source, label) {
                Ok(excerpt) => {
                    let marker = if has_primary_label && !label.primary { '-' } else { '^' };
                    excerpt.render(out, label, marker)?;
                    continue;
                },
                Err(reason) => {
                    let range = label.span.into_range();
                    writeln!(
                        out,
                        "  = source label unavailable (bytes {}..{} in {}): {reason}",
                        range.start,
                        range.end,
                        source.uri(),
                    )?;
                },
            }
        }
        if let Some(message) = label.label() {
            writeln!(out, "  = {message}")?;
        }
    }
    if let Some(help) = details.help {
        writeln!(out, "  help: {help}")?;
    }

    for related in details.related {
        render_diagnostic(out, related, source, depth + 1)?;
    }
    Ok(())
}

/// A validated byte range into the source file, with its line bounds.
struct Excerpt<'a> {
    source: &'a SourceFile,
    first_line: miden_debug_types::LineIndex,
    last_line: miden_debug_types::LineIndex,
}

impl<'a> Excerpt<'a> {
    fn new(source: &'a SourceFile, label: &Label) -> Result<Self, &'static str> {
        let span = label.span;
        if !span.source_id().is_unknown() && span.source_id() != source.id() {
            return Err("span belongs to another source file");
        }
        let range = span.into_slice_index();
        if range.start > range.end || range.end > source.len() {
            return Err("range is out of bounds");
        }
        if source.source_slice(range).is_none() {
            return Err("range splits a UTF-8 character");
        }
        let content = source.content();
        let first_line = content.line_index(span.start());
        let last_byte = span.end().to_u32().saturating_sub(1).max(span.start().to_u32());
        let last_line = content.line_index(ByteIndex::new(last_byte));
        Ok(Self { source, first_line, last_line })
    }

    fn render(&self, out: &mut impl Write, label: &Label, marker: char) -> fmt::Result {
        let content = self.source.content();
        let span = label.span.into_slice_index();
        let first = self.first_line.to_usize();
        let last = self.last_line.to_usize();

        if let Some(start) = content.line_start(self.first_line)
            && let Some(prefix) = self.source.as_str().get(start.to_usize()..span.start)
        {
            let column = display_column(prefix.trim_end_matches(['\r', '\n']), 0);
            writeln!(out, "  --> {}:{}:{}", self.source.uri(), first + 1, column + 1)?;
        }

        let context_start = first.saturating_sub(1);
        let context_end = (last + 1).min(content.last_line_index().to_usize());
        let gutter = (context_end + 1).ilog10() as usize + 1;
        for index in context_start..=context_end {
            let Some(range) = content.line_range((index as u32).into()) else {
                continue;
            };
            let start = range.start.to_usize();
            let Some(text) = self.source.as_str().get(start..range.end.to_usize()) else {
                continue;
            };
            let text =
                text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text);
            write!(out, " {:>gutter$} | ", index + 1)?;
            write_source_line(out, text)?;
            out.write_char('\n')?;
            if index < first || index > last {
                continue;
            }

            let label_start = span.start.saturating_sub(start).min(text.len());
            let label_end = span.end.saturating_sub(start).min(text.len());
            let Some(prefix) = text.get(..label_start) else {
                continue;
            };
            let Some(marked) = text.get(label_start..label_end) else {
                continue;
            };
            let column = display_column(prefix, 0);
            let width = (display_column(marked, column) - column).max(1);

            write!(out, " {:gutter$} : {:column$}", "", "")?;
            for _ in 0..width {
                out.write_char(marker)?;
            }
            if index == last
                && let Some(message) = label.label()
            {
                write!(out, " {message}")?;
            }
            out.write_char('\n')?;
        }

        Ok(())
    }
}

fn display_column(text: &str, column: usize) -> usize {
    text.chars().fold(column, |column, ch| column + display_width(ch, column))
}

fn display_width(ch: char, column: usize) -> usize {
    const TAB_WIDTH: usize = 4;
    if ch == '\t' {
        TAB_WIDTH - (column % TAB_WIDTH)
    } else {
        ch.width().unwrap_or(1)
    }
}

fn write_source_line(out: &mut impl Write, line: &str) -> fmt::Result {
    let mut column = 0;
    for ch in line.chars() {
        let width = display_width(ch, column);
        if ch == '\t' {
            write!(out, "{:width$}", "")?;
        } else if ch.is_control() {
            out.write_char('\u{fffd}')?;
        } else {
            out.write_char(ch)?;
        }
        column += width;
    }
    Ok(())
}
