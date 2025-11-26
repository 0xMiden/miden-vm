// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Felt, Path,
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, RelatedLabel, miette},
};
use miden_core::{FieldElement, utils::to_hex};

use super::name_resolver::SymbolResolutionError;

// LINKER ERROR
// ================================================================================================

/// An error which can be generated while linking modules and resolving procedure references.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[non_exhaustive]
pub enum LinkerError {
    #[error("there are no modules to analyze")]
    #[diagnostic()]
    Empty,
    #[error(transparent)]
    #[diagnostic(transparent)]
    SymbolResolution(#[from] Box<SymbolResolutionError>),
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
    DuplicateModule { path: Arc<Path> },
    #[error("undefined module '{path}'")]
    #[diagnostic()]
    UndefinedModule {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("undefined item '{path}'")]
    #[diagnostic(help(
        "you might be missing an import, or the containing library has not been linked"
    ))]
    UndefinedSymbol {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("invalid syscall: '{callee}' is not an exported kernel procedure")]
    #[diagnostic()]
    InvalidSysCallTarget {
        #[label("call occurs here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        callee: Arc<Path>,
    },
    #[error("invalid procedure reference: path refers to a non-procedure item")]
    #[diagnostic()]
    InvalidInvokeTarget {
        #[label("this path resolves to {path}, which is not a procedure")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
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
    #[error("invalid type reference")]
    #[diagnostic(help("the item this path resolves to is not a type definition"))]
    InvalidTypeRef {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
}
