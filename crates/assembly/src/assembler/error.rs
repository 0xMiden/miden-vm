use alloc::sync::Arc;

use miden_assembly_syntax::{
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, miette},
};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub(super) enum AssemblerError {
    #[error("control-flow nesting depth exceeded")]
    #[diagnostic(help("control-flow nesting exceeded the maximum depth of {max_depth}"))]
    ControlFlowNestingDepthExceeded {
        #[label("control-flow nesting exceeded the configured depth limit here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
}
