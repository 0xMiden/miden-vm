use alloc::sync::Arc;

use miden_assembly_syntax::{
    Path,
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, miette},
};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum AssemblerError {
    #[error("control-flow nesting depth exceeded")]
    #[diagnostic(help("control-flow nesting exceeded the maximum depth of {max_depth}"))]
    ControlFlowNestingDepthExceeded {
        #[label("control-flow nesting exceeded the configured depth limit here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
    #[error("duplicate definition found for export path '{path}'")]
    #[diagnostic()]
    DuplicateExportPath { path: Arc<Path> },
    #[error("invalid `@source_name` procedure attribute")]
    #[diagnostic(help(
        "expected exactly one quoted string, e.g. `@source_name(\"original name\")`"
    ))]
    InvalidSourceNameAttribute {
        #[label("this attribute does not have the form `@source_name(\"...\")`")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("number of procedure locals {num_locals} exceeds the maximum {max_locals}")]
    #[diagnostic(help(
        "number of procedure locals {num_locals} exceeds the maximum of {max_locals}"
    ))]
    TooManyProcedureLocals {
        #[label("this procedure declares more locals than are allowed")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        max_locals: u16,
        num_locals: u16,
    },
}
