use miden_debug_types::SourceSpan;
use miden_utils_diagnostics::{Diagnostic, Severity};

// This consumer deliberately has no `extern crate alloc` declaration.
#[derive(Debug, Diagnostic)]
#[diagnostic(severity(Warning), help("expected {expected}"))]
struct ExpectedToken {
    #[label("expected {expected}")]
    span: SourceSpan,
    expected: &'static str,
}

impl core::fmt::Display for ExpectedToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unexpected token")
    }
}

impl core::error::Error for ExpectedToken {}

#[test]
fn derive_uses_the_diagnostics_macro_exports() {
    let error = ExpectedToken {
        span: SourceSpan::UNKNOWN,
        expected: "procedure",
    };
    let details = error.details();
    assert_eq!(error.severity(), Severity::Warning);
    assert_eq!(details.help.as_deref(), Some("expected procedure"));
    assert_eq!(details.labels.len(), 1);
    assert_eq!(details.labels[0].label(), Some("expected procedure"));
}
