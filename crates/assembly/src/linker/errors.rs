use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Felt, LibraryPath,
    ast::QualifiedProcedureName,
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, RelatedLabel, miette},
};
use miden_core::{FieldElement, utils::to_hex};

// LINKER ERROR
// ================================================================================================

/// An error which can be generated while linking modules and resolving procedure references.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[non_exhaustive]
pub enum LinkerError {
    #[error("there are no modules to analyze")]
    #[diagnostic()]
    Empty,
    #[error("linking failed")]
    #[diagnostic(help("see diagnostics for details"))]
    Failed {
        #[related]
        labels: Box<[RelatedLabel]>,
    },
    #[error("found a cycle in the call graph, involving these procedures: {}", nodes.join(", "))]
    #[diagnostic()]
    Cycle { nodes: Box<[String]> },
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
    #[error("invalid syscall: '{callee}' is not an exported kernel procedure")]
    #[diagnostic()]
    InvalidSysCallTarget {
        #[label("call occurs here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        callee: Box<QualifiedProcedureName>,
    },
    #[error("value for key {} already present in the advice map", to_hex(Felt::elements_as_bytes(.key)))]
    #[diagnostic(help(
        "previous values at key were '{prev_values:?}'. Operation would have replaced them with '{new_values:?}'",
    ))]
    AdviceMapKeyAlreadyPresent {
        key: [Felt; 4],
        prev_values: Vec<Felt>,
        new_values: Vec<Felt>,
    },
    #[error("undefined type alias")]
    #[diagnostic()]
    UndefinedType {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
}
