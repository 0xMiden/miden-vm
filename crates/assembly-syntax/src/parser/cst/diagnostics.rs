use alloc::string::ToString;

use miden_assembly_syntax_cst::diagnostics::miette::MietteDiagnostic as CstDiagnostic;
use miden_debug_types::{SourceId, SourceSpan};

use crate::parser::ParsingError;

pub(super) fn lower_cst_diagnostics(
    source_id: SourceId,
    diagnostics: &[CstDiagnostic],
) -> Option<ParsingError> {
    diagnostics
        .first()
        .map(|diagnostic| lower_cst_diagnostic(source_id, diagnostic))
}

fn lower_cst_diagnostic(source_id: SourceId, diagnostic: &CstDiagnostic) -> ParsingError {
    let label = diagnostic.labels.as_deref().and_then(|labels| labels.first());
    let span = label
        .map(|label| {
            let span = label.inner();
            SourceSpan::new(
                source_id,
                (span.offset() as u32)..((span.offset() + span.len()) as u32),
            )
        })
        .unwrap_or_else(|| SourceSpan::at(source_id, 0u32));
    let message = label
        .and_then(|label| label.label())
        .map(str::to_string)
        .unwrap_or_else(|| diagnostic.to_string());

    if message.starts_with("unrecognized token `") {
        ParsingError::InvalidToken { span }
    } else {
        ParsingError::InvalidSyntax { span, message }
    }
}
