use alloc::{format, sync::Arc};
use core::{error::Error, fmt};

use miden_debug_types::{SourceFile, SourceId, SourceLanguage, SourceSpan, Uri};

use crate::{IntoDiagnostic, Label, RelatedLabel, Report, WrapErr};

fn source(text: &str) -> Arc<SourceFile> {
    Arc::new(SourceFile::new(
        SourceId::new(1),
        SourceLanguage::Masm,
        Uri::new("test.masm"),
        text,
    ))
}

#[test]
fn renders_multiline_spans_with_tabs_crlf_and_wide_characters() {
    let file = source("\t界x\r\nnext\r\n");
    let span = SourceSpan::new(file.id(), 4..8);
    let error = RelatedLabel::error("bad input")
        .with_source_file(Some(file))
        .with_labeled_span(span, "check this");

    let rendered = format!("{:?}", Report::new(error));
    assert!(rendered.contains("test.masm:1:7"), "{rendered}");
    assert!(rendered.contains("1 |     界x\n   :       ^"), "{rendered}");
    assert!(rendered.contains("2 | next\n   : ^ check this"), "{rendered}");
    assert!(!rendered.contains(['\t', '\r']), "{rendered}");
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
