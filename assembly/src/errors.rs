use alloc::{string::String, sync::Arc, vec::Vec};

use vm_core::mast::MastForestError;

use crate::{
    LibraryNamespace, LibraryPath, SourceSpan,
    ast::QualifiedProcedureName,
    diagnostics::{Diagnostic, RelatedError, RelatedLabel, SourceFile},
};

// ASSEMBLY ERROR
// ================================================================================================

/// An error which can be generated while compiling a Miden assembly program into a MAST.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum AssemblyError {
    #[error("there are no modules to analyze")]
    #[diagnostic()]
    Empty,
    #[error("assembly failed")]
    #[diagnostic(help("see diagnostics for details"))]
    Failed {
        #[related]
        labels: Vec<RelatedLabel>,
    },
    #[error("found a cycle in the call graph, involving these procedures: {}", nodes.as_slice().join(", "))]
    #[diagnostic()]
    Cycle { nodes: Vec<String> },
    #[error(
        "two procedures found with same mast root, but conflicting definitions ('{first}' and '{second}')"
    )]
    #[diagnostic()]
    ConflictingDefinitions {
        first: QualifiedProcedureName,
        second: QualifiedProcedureName,
    },
    #[error("duplicate definition found for module '{path}'")]
    #[diagnostic()]
    DuplicateModule { path: LibraryPath },
    #[error("undefined module '{path}'")]
    #[diagnostic()]
    UndefinedModule {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: LibraryPath,
    },
    #[error("module namespace is inconsistent with library ('{actual}' vs '{expected}')")]
    #[diagnostic()]
    InconsistentNamespace {
        expected: LibraryNamespace,
        actual: LibraryNamespace,
    },
    #[error("invalid syscall: '{callee}' is not an exported kernel procedure")]
    #[diagnostic()]
    InvalidSysCallTarget {
        #[label("call occurs here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        callee: QualifiedProcedureName,
    },
    #[error("invalid local word index: {local_addr}")]
    #[diagnostic(help("the index to a local word must be a multiple of 4"))]
    InvalidLocalWordIndex {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        local_addr: u16,
    },
    #[error("invalid parameter value: {param}; expected to be between {min} and {max}")]
    #[diagnostic()]
    InvalidU8Param {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        param: u8,
        min: u8,
        max: u8,
    },
    #[error("invalid use of 'caller' instruction outside of kernel")]
    #[diagnostic(help(
        "the 'caller' instruction is only allowed in procedures defined in a kernel"
    ))]
    CallerOutsideOfKernel {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },

    #[error("invalid procedure: body must contain at least one instruction if it has decorators")]
    #[diagnostic()]
    EmptyProcedureBodyWithDecorators {
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error(transparent)]
    #[diagnostic(transparent)]
    Other(RelatedError),
    // Technically MastForestError is the source error here, but since AssemblyError is converted
    // into a Report and that doesn't implement core::error::Error, treating MastForestError as a
    // source error would effectively swallow it, so we include it in the error message instead.
    #[error("{0}: {1}")]
    Forest(&'static str, MastForestError),
}

impl AssemblyError {
    pub(super) fn forest_error(message: &'static str, source: MastForestError) -> Self {
        Self::Forest(message, source)
    }
}
