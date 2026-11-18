use alloc::sync::Arc;

use miden_assembly_syntax::{
    Path,
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, DiagnosticDetails, Label},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum AssemblerError {
    #[error("control-flow nesting depth exceeded")]
    ControlFlowNestingDepthExceeded {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
    #[error("duplicate definition found for export path '{path}'")]
    DuplicateExportPath { path: Arc<Path> },
    #[error("invalid `@source_name` procedure attribute")]
    InvalidSourceNameAttribute {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("number of procedure locals {num_locals} exceeds the maximum {max_locals}")]
    TooManyProcedureLocals {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        max_locals: u16,
        num_locals: u16,
    },
}

impl Diagnostic for AssemblerError {
    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::ControlFlowNestingDepthExceeded { span, source_file, max_depth } => {
                DiagnosticDetails {
                    source: source_file.as_deref(),
                    labels: alloc::vec![Label::new(
                        *span,
                        "control-flow nesting exceeded the configured depth limit here"
                    )]
                    .into(),
                    help: Some(
                        format!("control-flow nesting exceeded the maximum depth of {max_depth}")
                            .into(),
                    ),
                    ..DiagnosticDetails::default()
                }
            },
            Self::InvalidSourceNameAttribute { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this attribute does not have the form `@source_name(\"...\")`"
                )]
                .into(),
                help: Some(
                    "expected exactly one quoted string, e.g. `@source_name(\"original name\")`"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::TooManyProcedureLocals {
                span,
                source_file,
                max_locals,
                num_locals,
            } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this procedure declares more locals than are allowed"
                )]
                .into(),
                help: Some(
                    format!(
                        "number of procedure locals {num_locals} exceeds the maximum of \
                         {max_locals}"
                    )
                    .into(),
                ),
                ..DiagnosticDetails::default()
            },
            _ => DiagnosticDetails::default(),
        }
    }
}
