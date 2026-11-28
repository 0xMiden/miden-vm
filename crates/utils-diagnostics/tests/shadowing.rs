use miden_debug_types::SourceSpan;
use miden_utils_diagnostics::Diagnostic;

#[derive(Debug, Diagnostic)]
#[diagnostic(help("{details}"))]
struct CapturedDetails {
    details: String,
    #[label("{details}")]
    span: SourceSpan,
}

impl core::fmt::Display for CapturedDetails {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("captured details")
    }
}

impl core::error::Error for CapturedDetails {}

#[test]
fn derive_keeps_field_captures_distinct_from_generated_bindings() {
    let error = CapturedDetails {
        details: String::from("expected a procedure"),
        span: SourceSpan::UNKNOWN,
    };
    let details = error.details();
    assert_eq!(details.help.as_deref(), Some("expected a procedure"));
    assert_eq!(details.labels[0].label(), Some("expected a procedure"));
}
