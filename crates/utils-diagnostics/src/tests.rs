use alloc::{boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use core::{error::Error, fmt};

use miden_debug_types::{SourceFile, SourceId, SourceLanguage, SourceSpan, Uri};

use crate::{Diagnostic, IntoDiagnostic, Label, RelatedLabel, Report, Severity, WrapErr};

fn source(text: &str) -> Arc<SourceFile> {
    Arc::new(SourceFile::new(
        SourceId::new(1),
        SourceLanguage::Masm,
        Uri::new("test.masm"),
        text,
    ))
}

#[derive(Debug, Diagnostic)]
enum DerivedDiagnostic {
    #[diagnostic(severity(Warning), code(test::metadata), help("expected {expected}"))]
    Annotated {
        #[source_code]
        source: Arc<SourceFile>,
        #[label(primary, "expected {expected}")]
        span: SourceSpan,
        #[label(collection)]
        labels: Vec<Label>,
        #[related]
        related: Vec<RelatedLabel>,
        expected: &'static str,
    },
    #[diagnostic(transparent)]
    Transparent(Box<DerivedDiagnostic>),
    #[diagnostic(forward(inner))]
    Forward {
        inner: Box<DerivedDiagnostic>,
        #[source_code]
        source: Option<Arc<SourceFile>>,
        #[label]
        span: SourceSpan,
    },
    Collection {
        #[label(collection)]
        labels: Vec<Label>,
        #[help]
        help: Option<String>,
    },
}

impl fmt::Display for DerivedDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("derived diagnostic")
    }
}

impl Error for DerivedDiagnostic {}

#[test]
fn derive_preserves_mixed_labels_and_forwarded_metadata() {
    let file = source("begin\nend");
    let span = SourceSpan::new(file.id(), 0..5);
    let secondary = SourceSpan::new(file.id(), 6..9);
    let error = DerivedDiagnostic::Annotated {
        source: file.clone(),
        span,
        labels: vec![Label::new(secondary, "other declaration")],
        related: vec![RelatedLabel::advice("related note")],
        expected: "procedure",
    };
    let details = error.details();
    assert_eq!(error.severity(), Severity::Warning);
    assert_eq!(details.code, Some("test::metadata"));
    assert_eq!(details.help.as_deref(), Some("expected procedure"));
    assert_eq!(details.source.unwrap().id(), file.id());
    assert_eq!(details.labels.len(), 2);
    assert!(details.labels[0].primary);
    assert_eq!(details.labels[0].span, span);
    assert_eq!(details.labels[0].label(), Some("expected procedure"));
    assert_eq!(details.labels[1].span, secondary);
    assert_eq!(details.related.len(), 1);
    assert_eq!(details.related[0].severity(), Severity::Advice);
    drop(details);

    let transparent = DerivedDiagnostic::Transparent(Box::new(error));
    assert_eq!(transparent.severity(), Severity::Warning);
    assert_eq!(transparent.details().labels.len(), 2);
    let forwarded = DerivedDiagnostic::Forward {
        inner: Box::new(transparent),
        source: None,
        span: secondary,
    };
    let details = forwarded.details();
    assert_eq!(forwarded.severity(), Severity::Warning);
    assert_eq!(details.help.as_deref(), Some("expected procedure"));
    assert_eq!(details.code, Some("test::metadata"));
    assert!(details.source.is_none());
    assert_eq!(details.labels.len(), 1);
    assert_eq!(details.labels[0].span, secondary);
    assert_eq!(details.related.len(), 1);
}

#[test]
fn derive_borrows_label_collections_and_optional_help() {
    let error = DerivedDiagnostic::Collection {
        labels: vec![Label::underline(SourceSpan::UNKNOWN)],
        help: Some(String::from("check this")),
    };
    let details = error.details();
    assert!(matches!(details.labels, alloc::borrow::Cow::Borrowed(_)));
    assert_eq!(details.help.as_deref(), Some("check this"));
    let missing = DerivedDiagnostic::Collection { labels: Vec::new(), help: None };
    assert!(missing.details().help.is_none());
}

#[test]
fn renders_multiline_spans_with_tabs_crlf_and_wide_characters() {
    let file = source("\t界x\r\nnext\r\n");
    let span = SourceSpan::new(file.id(), 4..8);
    let error = RelatedLabel::error("bad input")
        .with_source_file(Some(file))
        .with_labeled_span(span, "check this");

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("test.masm:1:3"), "{rendered}");
    assert!(rendered.contains("1 |     界x\n   :       ^"), "{rendered}");
    assert!(rendered.contains("2 | next\n   : ^ check this"), "{rendered}");
    assert!(!rendered.contains(['\t', '\r']), "{rendered}");
}

#[test]
fn eof_anchor_inside_crlf_uses_the_visible_end_of_line() {
    let file = source("begin\r\n");
    let span = SourceSpan::at(file.id(), 6);
    let error = RelatedLabel::error("missing end")
        .with_source_file(Some(file))
        .with_labeled_span(span, "expected end");

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("test.masm:1:6"), "{rendered}");
    assert!(rendered.contains("1 | begin\n   :      ^ expected end"), "{rendered}");
}

#[test]
fn renders_empty_source_and_retains_labels_when_an_excerpt_is_unavailable() {
    let file = source("");
    let point = SourceSpan::at(file.id(), 0);
    let error = RelatedLabel::error("unexpected EOF")
        .with_source_file(Some(file))
        .with_labeled_span(point, "expected a token")
        .with_label(Label::underline(SourceSpan::new(point.source_id(), 1..2)));

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("test.masm:1:1"), "{rendered}");
    assert!(rendered.contains("^ expected a token"), "{rendered}");
    assert!(
        rendered.contains("bytes 1..2 in test.masm): range is out of bounds"),
        "{rendered}"
    );

    let file = source("§");
    let invalid = SourceSpan::new(file.id(), 1..2);
    let foreign = SourceSpan::new(SourceId::new(2), 0..2);
    let error = RelatedLabel::error("invalid locations")
        .with_source_file(Some(file))
        .with_labeled_span(invalid, "inside a codepoint")
        .with_labeled_span(foreign, "another file")
        .with_labeled_span(SourceSpan::SYNTHETIC, "generated code");
    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("range splits a UTF-8 character"), "{rendered}");
    assert!(rendered.contains("span belongs to another source file"), "{rendered}");
    assert_eq!(rendered.matches("source label unavailable").count(), 2, "{rendered}");
    assert!(rendered.contains("= inside a codepoint"), "{rendered}");
    assert!(rendered.contains("= another file"), "{rendered}");
    assert!(rendered.contains("= generated code"), "{rendered}");
    assert!(!rendered.contains("-->"), "{rendered}");

    let missing = RelatedLabel::error("missing source").with_labeled_span(point, "here");
    let rendered = format!("{:?}", Report::new(missing));
    assert!(rendered.contains("= here"), "{rendered}");
    assert!(!rendered.contains("source label unavailable"), "{rendered}");
}

#[test]
fn skips_unknown_and_synthetic_locations_but_keeps_their_labels() {
    for source_id in [SourceId::new(1), SourceId::UNKNOWN] {
        let file = Arc::new(SourceFile::new(
            source_id,
            SourceLanguage::Masm,
            Uri::new("test.masm"),
            "begin",
        ));
        let error = RelatedLabel::error("bad input")
            .with_source_file(Some(file))
            .with_labeled_span(SourceSpan::UNKNOWN, "unknown location")
            .with_labeled_span(SourceSpan::SYNTHETIC, "generated code");

        let rendered = format!("{:?}", Report::new(error));
        assert!(rendered.contains("= unknown location"), "{rendered}");
        assert!(rendered.contains("= generated code"), "{rendered}");
        assert!(!rendered.contains("-->"), "{rendered}");
        assert!(!rendered.contains("source label unavailable"), "{rendered}");
    }

    // Detached CST spans still use their byte range when source is attached later.
    let detached = RelatedLabel::error("detached input")
        .with_source_file(Some(source("x")))
        .with_labeled_span(SourceSpan::new(SourceId::UNKNOWN, 0..1), "token");
    let rendered = format!("{:?}", Report::new(detached));
    assert!(rendered.contains("test.masm:1:1"), "{rendered}");
    assert!(rendered.contains("^ token"), "{rendered}");
}

#[test]
fn escapes_controls_in_diagnostic_text_and_keeps_line_breaks() {
    let file = source("\u{7}a");
    let span = SourceSpan::new(file.id(), 0..1);
    let error = RelatedLabel::error("\u{7} heading\nnext line")
        .with_source_file(Some(file))
        .with_labeled_span(span, "label \u{7}")
        .with_help("watch for \u{85}");

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("error: \\u{7} heading\nnext line\n"), "{rendered}");
    assert!(rendered.contains("1 | \u{fffd}a\n   : ^ label \\u{7}"), "{rendered}");
    assert!(rendered.contains("help: watch for \\u{85}"), "{rendered}");
    assert!(!rendered.chars().any(|ch| ch != '\n' && ch.is_control()), "{rendered}");
}

#[test]
fn keeps_source_paths_and_inline_labels_on_one_line() {
    let file = Arc::new(SourceFile::new(
        SourceId::new(1),
        SourceLanguage::Masm,
        Uri::new("my\nfile.masm"),
        "begin\n",
    ));
    let span = SourceSpan::new(file.id(), 0..5);
    let invalid = SourceSpan::new(file.id(), 7..8);
    let error = RelatedLabel::error("syntax error")
        .with_source_file(Some(file))
        .with_labeled_span(span, "first\nsecond line")
        .with_labeled_span(invalid, "past\nend");

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("  --> my\\nfile.masm:1:1\n"), "{rendered}");
    assert!(rendered.contains("^^^^^ first\\nsecond line\n"), "{rendered}");
    assert!(
        rendered.contains("bytes 7..8 in my\\nfile.masm): range is out of bounds\n"),
        "{rendered}"
    );
    assert!(rendered.contains("= past\\nend\n"), "{rendered}");
}

#[derive(Debug)]
struct OriginalError;

impl fmt::Display for OriginalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original failure")
    }
}

impl Error for OriginalError {}

#[test]
fn failed_downcast_preserves_context_and_typed_cause() {
    let report = Err::<(), _>(OriginalError)
        .into_diagnostic()
        .wrap_err("outer message")
        .unwrap_err();

    let report = report.downcast::<fmt::Error>().unwrap_err();
    assert!(report.downcast_ref::<OriginalError>().is_some());
    assert!(report.source().unwrap().downcast_ref::<OriginalError>().is_some());
    assert_eq!(format!("{report}"), "outer message");
    assert!(format!("{report:?}").contains("caused by: original failure"));
    assert!(report.downcast::<OriginalError>().is_ok());
}
