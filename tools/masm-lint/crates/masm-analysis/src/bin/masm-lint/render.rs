//! Clippy-style terminal diagnostic rendering.

use std::fmt::Write;

use masm_analysis::lint::LintDiagnostic;
use miden_debug_types::{SourceManager, SourceSpan};
use yansi::Paint as _;

/// Render a single diagnostic to stdout in clippy/rustc style.
pub fn render_diagnostic(diag: &LintDiagnostic, sources: &dyn SourceManager) {
    print!("{}", render_diagnostic_to_string(diag, sources));
}

/// Render a single diagnostic to a string.
///
/// This produces the same output as [`render_diagnostic`] but returns it
/// instead of printing to stdout, which is useful for testing.
pub fn render_diagnostic_to_string(diag: &LintDiagnostic, sources: &dyn SourceManager) -> String {
    let mut out = String::new();
    write_diagnostic(&mut out, diag, sources);
    out
}

/// Write a single diagnostic in clippy/rustc style.
///
/// Output format:
/// ```text
/// warning: <message>
///   --> file:line:col
///    |
/// NN | source line
///    | ^^^^^^^^^^^
///    |
///    ::: file:line:col
///    |
/// NN | source line
///    | ^^^
///    = help: <related message>
///    = note: <note>
/// ```
fn write_diagnostic(out: &mut impl Write, diag: &LintDiagnostic, sources: &dyn SourceManager) {
    // Heading: warning message.
    writeln!(out, "{}: {}", "warning".yellow().bold(), diag.message.bold()).unwrap();

    // Primary location.
    if let Some(loc) = location_string(diag.span, sources) {
        writeln!(out, "  {} {}", "-->".cyan().bold(), loc).unwrap();
        write_snippet(out, diag.span, sources, "    ");
    }

    // Related spans.
    for related in &diag.related {
        if let Some(loc) = location_string(related.span, sources) {
            writeln!(out, "    {} {}", ":::".cyan().bold(), loc).unwrap();
            write_snippet(out, related.span, sources, "    ");
            writeln!(out, "    {} help: {}", "=".cyan().bold(), related.message).unwrap();
        }
    }

    // Procedure note.
    writeln!(out, "    {} note: {}", "=".cyan().bold(), diag.note).unwrap();
    writeln!(out).unwrap();
}

/// Format a span as `file:line:col`, stripping the `file://` prefix.
///
/// Returns `None` when the span cannot be resolved.
fn location_string(span: SourceSpan, sources: &dyn SourceManager) -> Option<String> {
    if span == SourceSpan::UNKNOWN {
        return None;
    }
    let flc = sources.file_line_col(span).ok()?;
    let raw_uri = flc.uri.as_str();
    let path = strip_file_scheme(raw_uri);
    Some(format!("{}:{}:{}", path, flc.line.to_usize(), flc.column.to_usize()))
}

/// Strip the `file://` (or `file:`) scheme prefix from a URI for display.
fn strip_file_scheme(uri: &str) -> &str {
    if let Some(rest) = uri.strip_prefix("file://") {
        return rest;
    }
    if let Some(rest) = uri.strip_prefix("file:") {
        return rest;
    }
    uri
}

/// Write a source snippet for `span` with `|` gutter and `^^^` carets.
///
/// `indent` is prepended to every line of output (typically four spaces so
/// the snippet aligns with the `-->` arrow).
fn write_snippet(
    out: &mut impl Write,
    span: SourceSpan,
    sources: &dyn SourceManager,
    indent: &str,
) {
    let Some((line_text, line_number, col_zero)) = resolve_line(span, sources) else {
        return;
    };

    // Width of the gutter: enough digits for the line number.
    let gutter_width = decimal_width(line_number);
    let gutter_pad = " ".repeat(gutter_width);

    // Blank gutter separator.
    writeln!(out, "{}{} {}", indent, gutter_pad, "|".cyan().bold()).unwrap();

    // Source line.
    writeln!(
        out,
        "{}{} {} {}",
        indent,
        line_number.cyan().bold(),
        "|".cyan().bold(),
        line_text
    )
    .unwrap();

    // Carets.
    let span_len = span_display_len(span, sources);
    let col_spaces = " ".repeat(col_zero);
    let carets = "^".repeat(span_len.max(1));
    writeln!(
        out,
        "{}{} {} {}{}",
        indent,
        gutter_pad,
        "|".cyan().bold(),
        col_spaces,
        carets.yellow().bold()
    )
    .unwrap();
}

/// Resolve the source line text, one-indexed line number, and zero-indexed column
/// offset for the start of `span`.
///
/// Returns `None` if the span cannot be resolved.
fn resolve_line(span: SourceSpan, sources: &dyn SourceManager) -> Option<(String, usize, usize)> {
    let flc = sources.file_line_col(span).ok()?;

    // line is one-indexed; lines().nth() is zero-indexed.
    let line_idx = flc.line.to_usize().checked_sub(1)?;
    let col_zero = flc.column.to_usize().saturating_sub(1);

    let source_file = sources.get(span.source_id()).ok()?;
    let line_text = source_file.as_str().lines().nth(line_idx)?.to_owned();

    Some((line_text, flc.line.to_usize(), col_zero))
}

/// Return the display length (in chars) of the source text covered by `span`.
///
/// Falls back to 1 when the slice cannot be resolved.
fn span_display_len(span: SourceSpan, sources: &dyn SourceManager) -> usize {
    sources.source_slice(span).ok().map(|s| s.chars().count()).unwrap_or(1)
}

/// Return the number of decimal digits needed to represent `n`.
fn decimal_width(n: usize) -> usize {
    n.to_string().len()
}

#[cfg(test)]
mod tests {
    use masm_analysis::lint::{LintDiagnostic, RelatedSpan};
    use miden_debug_types::{DefaultSourceManager, SourceLanguage, SourceManager, SourceSpan, Uri};

    use super::*;

    fn source_manager_with_fixture() -> (DefaultSourceManager, SourceSpan, SourceSpan) {
        let sources = DefaultSourceManager::default();
        let file = sources.load(
            SourceLanguage::Masm,
            Uri::new("file:///tmp/render_fixture.masm"),
            "begin\n    adv_push\nend\n".to_string(),
        );
        let primary = SourceSpan::new(file.id(), 10..18);
        let related = SourceSpan::new(file.id(), 0..5);
        (sources, primary, related)
    }

    #[test]
    fn render_diagnostic_to_string_strips_file_scheme_and_renders_related_spans() {
        yansi::disable();
        let (sources, primary, related) = source_manager_with_fixture();
        let diagnostic = LintDiagnostic {
            message: "unconstrained advice reaches a u32 operation".to_string(),
            span: primary,
            note: "in procedure `test`".to_string(),
            related: vec![RelatedSpan {
                span: related,
                message: "advice value originates here".to_string(),
            }],
        };

        let rendered = render_diagnostic_to_string(&diagnostic, &sources);

        assert!(rendered.contains("warning: unconstrained advice reaches a u32 operation"));
        assert!(rendered.contains("--> /tmp/render_fixture.masm:2:5"));
        assert!(rendered.contains("adv_push"));
        assert!(rendered.contains("^^^^^^^^"));
        assert!(rendered.contains("::: /tmp/render_fixture.masm:1:1"));
        assert!(rendered.contains("help: advice value originates here"));
        assert!(rendered.contains("note: in procedure `test`"));
    }

    #[test]
    fn render_diagnostic_to_string_handles_unknown_primary_span() {
        yansi::disable();
        let sources = DefaultSourceManager::default();
        let diagnostic = LintDiagnostic {
            message: "synthetic diagnostic".to_string(),
            span: SourceSpan::UNKNOWN,
            note: "no source location available".to_string(),
            related: Vec::new(),
        };

        let rendered = render_diagnostic_to_string(&diagnostic, &sources);

        assert!(rendered.contains("warning: synthetic diagnostic"));
        assert!(!rendered.contains("-->"));
        assert!(rendered.contains("note: no source location available"));
    }
}
