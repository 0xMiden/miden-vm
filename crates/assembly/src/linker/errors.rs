// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Felt, Path, Word,
    ast::{SymbolResolutionError, constants::ConstEvalError},
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, RelatedError, RelatedLabel, miette},
};
use miden_core::mast::MastNodeId;

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
    #[error(transparent)]
    #[diagnostic(transparent)]
    ConstEval(#[from] Box<ConstEvalError>),
    #[error("linking failed")]
    #[diagnostic(help("see diagnostics for details"))]
    Related {
        #[related]
        errors: Box<[RelatedError]>,
    },
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
    #[error("invalid module surface metadata for package '{package}': {reason}")]
    #[diagnostic()]
    InvalidPackageModuleSurface { package: String, reason: String },
    #[error("ambiguous module path resolution for '{path}'")]
    #[diagnostic(help("matching module prefixes: {}", matches.join(", ")))]
    AmbiguousModulePath {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
        matches: Box<[String]>,
    },
    #[error("undefined module '{path}'")]
    #[diagnostic()]
    UndefinedModule {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("private submodule '{module}'")]
    #[diagnostic(help("only public submodules can be imported from another module"))]
    PrivateSubmodule {
        #[label("this submodule is private")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        module: Arc<Path>,
        #[related]
        defined: Option<RelatedLabel>,
    },
    #[error(
        "module '{path}' is not declared by its parent module '{parent}' as `mod {name}` or `pub mod {name}`"
    )]
    #[diagnostic(help(
        "source modules must be declared by their parent module before they can be linked as descendants"
    ))]
    UndeclaredSubmodule {
        path: Arc<Path>,
        parent: Arc<Path>,
        name: String,
    },
    #[error(
        "name conflict in module '{module}': {kind} '{name}' conflicts with an existing item, import, or submodule"
    )]
    #[diagnostic()]
    NamespaceNameConflict {
        #[label("conflicting namespace member")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        module: Arc<Path>,
        name: String,
        kind: &'static str,
    },
    #[error("modules cannot be re-exported with `pub use`: '{path}'")]
    #[diagnostic(help(
        "declare the module with `pub mod` in its parent module instead of re-exporting it"
    ))]
    ModuleReExport {
        #[label("this `pub use` resolves to a module")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("module import target '{path}' resolved to an item")]
    #[diagnostic(help(
        "module-form imports must target modules; use `use {{item}} from module` for items"
    ))]
    InvalidModuleImportTarget {
        #[label("this import expects a module target")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("item import target '{path}' resolved to a module")]
    #[diagnostic(help("item-form imports may only import procedures, constants, or types"))]
    InvalidItemImportTarget {
        #[label("this import expects an item target")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("import re-export cycle involving '{path}'")]
    #[diagnostic(help("public item re-exports must not form cycles"))]
    ImportReExportCycle {
        #[label("this import participates in a re-export cycle")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("import target '{path}' cannot be resolved through import '{alias}'")]
    #[diagnostic(help(
        "imports are resolved independently; use the original global path instead of another import alias"
    ))]
    ImportTargetUsesImport {
        #[label("this import target starts with another import alias")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
        alias: String,
    },
    #[error("self-referential import of module '{path}'")]
    #[diagnostic(help(
        "a module cannot import itself; reference local items directly or use absolute paths in code"
    ))]
    SelfReferentialImport {
        #[label("this import resolves to the module that contains it")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("cannot import submodule '{path}' declared in the same module")]
    #[diagnostic(help(
        "reference the submodule directly with a submodule-qualified path instead of importing it"
    ))]
    ImportTargetIsLocalSubmodule {
        #[label("this import resolves to a submodule declared in the same scope")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("invalid relative item path '{path}'")]
    #[diagnostic(help(
        "item paths must be absolute, local, or qualified by an import or submodule in the current module"
    ))]
    InvalidRelativePath {
        #[label("this path does not start with a local item, import, or submodule")]
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
    #[error("ambiguous dynamic procedure link for MAST root {mast_root}")]
    #[diagnostic(help(
        "link the library statically, or avoid exporting multiple procedures with this same execution digest"
    ))]
    AmbiguousDynamicProcedureRoot {
        #[label("dynamic reference cannot select one of the same-digest exported roots")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        mast_root: Word,
        source_library_commitment: Word,
        selected_root: MastNodeId,
        conflicting_root: MastNodeId,
    },
    #[error("kernel procedure '{callee}' can only be invoked via syscall")]
    #[diagnostic()]
    KernelProcNotSyscall {
        #[label("non-syscall reference to kernel procedure")]
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
    #[error("value for key {key} already present in the advice map")]
    #[diagnostic(help(
        "previous values at key were '{prev_values:?}'. Operation would have replaced them with '{new_values:?}'",
    ))]
    AdviceMapKeyAlreadyPresent {
        key: Word,
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
    #[error("invalid constant reference")]
    #[diagnostic(help("the item this path resolves to is not a constant definition"))]
    InvalidConstantRef {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
}

impl From<SymbolResolutionError> for LinkerError {
    #[inline]
    fn from(value: SymbolResolutionError) -> Self {
        Self::SymbolResolution(Box::new(value))
    }
}

impl From<ConstEvalError> for LinkerError {
    #[inline]
    fn from(value: ConstEvalError) -> Self {
        Self::ConstEval(Box::new(value))
    }
}
