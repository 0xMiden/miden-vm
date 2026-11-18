use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Felt, Path, Word,
    ast::{ModuleIndex, SymbolResolutionError, constants::ConstEvalError},
    debuginfo::{SourceFile, SourceSpan},
    diagnostics::{Diagnostic, DiagnosticDetails, Label, RelatedError, RelatedLabel},
};

// LINKER ERROR
// ================================================================================================

/// An error which can be generated while linking modules and resolving procedure references.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkerError {
    #[error("there are no modules to analyze")]
    Empty,
    #[error(transparent)]
    SymbolResolution(#[from] Box<SymbolResolutionError>),
    #[error(transparent)]
    ConstEval(#[from] Box<ConstEvalError>),
    #[error("linking failed")]
    Related { errors: Box<[RelatedError]> },
    #[error("linking failed")]
    Failed { labels: Box<[RelatedLabel]> },
    #[error("found a cycle in the call graph, involving these procedures: {}", nodes.join(", "))]
    Cycle { nodes: Box<[String]> },
    #[error("duplicate definition found for module '{path}'")]
    DuplicateModule { path: Arc<Path> },
    #[error("too many modules in the graph (maximum: {})", ModuleIndex::MAX_MODULES)]
    TooManyModules,
    #[error("invalid module surface metadata for package '{package}': {reason}")]
    InvalidPackageModuleSurface { package: String, reason: String },
    #[error("ambiguous module path resolution for '{path}'")]
    AmbiguousModulePath {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
        matches: Box<[String]>,
    },
    #[error("undefined module '{path}'")]
    UndefinedModule {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("private submodule '{module}'")]
    PrivateSubmodule {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        module: Arc<Path>,
        defined: Option<RelatedLabel>,
    },
    #[error(
        "module '{path}' is not declared by its parent module '{parent}' as `mod {name}` or `pub mod {name}`"
    )]
    UndeclaredSubmodule {
        path: Arc<Path>,
        parent: Arc<Path>,
        name: String,
    },
    #[error(
        "name conflict in module '{module}': {kind} '{name}' conflicts with an existing item, import, or submodule"
    )]
    NamespaceNameConflict {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        module: Arc<Path>,
        name: String,
        kind: &'static str,
    },
    #[error("modules cannot be re-exported with `pub use`: '{path}'")]
    ModuleReExport {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("module import target '{path}' resolved to an item")]
    InvalidModuleImportTarget {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("item import target '{path}' resolved to a module")]
    InvalidItemImportTarget {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("invalid re-export of kernel syscall '{path}'")]
    InvalidReExportOfKernelSyscall {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("import re-export cycle involving '{path}'")]
    ImportReExportCycle {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("import target '{path}' cannot be resolved through import '{alias}'")]
    ImportTargetUsesImport {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
        alias: String,
    },
    #[error("self-referential import of module '{path}'")]
    SelfReferentialImport {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("cannot import submodule '{path}' declared in the same module")]
    ImportTargetIsLocalSubmodule {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("invalid relative item path '{path}'")]
    InvalidRelativePath {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("undefined item '{path}'")]
    UndefinedSymbol {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("invalid syscall: '{callee}' is not an exported kernel procedure")]
    InvalidSysCallTarget {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        callee: Arc<Path>,
    },
    #[error("kernel procedure '{callee}' can only be invoked via syscall")]
    KernelProcNotSyscall {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        callee: Arc<Path>,
    },
    #[error("invalid procedure reference: path refers to a non-procedure item")]
    InvalidInvokeTarget {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        path: Arc<Path>,
    },
    #[error("value for key {key} already present in the advice map")]
    AdviceMapKeyAlreadyPresent {
        key: Word,
        prev_values: Vec<Felt>,
        new_values: Vec<Felt>,
    },
    #[error("undefined type alias")]
    UndefinedType {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("recursive type definition")]
    RecursiveType {
        span: SourceSpan,
        cycle_span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid type reference")]
    InvalidTypeRef {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid constant reference")]
    InvalidConstantRef {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
}

impl Diagnostic for LinkerError {
    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::SymbolResolution(error) => error.details(),
            Self::ConstEval(error) => error.details(),
            Self::Related { errors } => DiagnosticDetails {
                help: Some("see diagnostics for details".into()),
                related: errors.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::Failed { labels } => DiagnosticDetails {
                help: Some("see diagnostics for details".into()),
                related: labels.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::AmbiguousModulePath { span, source_file, matches, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(format!("matching module prefixes: {}", matches.join(", ")).into()),
                ..DiagnosticDetails::default()
            },
            Self::UndefinedModule { span, source_file, .. }
            | Self::UndefinedType { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                ..DiagnosticDetails::default()
            },
            Self::PrivateSubmodule { span, source_file, defined, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this submodule is private")].into(),
                help: Some("only public submodules can be imported from another module".into()),
                related: defined.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::UndeclaredSubmodule { .. } => DiagnosticDetails {
                help: Some(
                    "source modules must be declared by their parent module before they can be \
                     linked as descendants"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::NamespaceNameConflict { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "conflicting namespace member")].into(),
                ..DiagnosticDetails::default()
            },
            Self::ModuleReExport { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this `pub use` resolves to a module")]
                    .into(),
                help: Some(
                    "declare the module with `pub mod` in its parent module instead of \
                     re-exporting it"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidModuleImportTarget { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this import expects a module target")]
                    .into(),
                help: Some(
                    "module-form imports must target modules; use `use {{item}} from module` for \
                     items"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidItemImportTarget { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this import expects an item target")].into(),
                help: Some(
                    "item-form imports may only import procedures, constants, or types".into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidReExportOfKernelSyscall { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this import attempts to re-export a kernel syscall"
                )]
                .into(),
                help: Some(
                    "re-export of kernel procedures is not permitted, except from the kernel root"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::ImportReExportCycle { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this import participates in a re-export cycle"
                )]
                .into(),
                help: Some("public item re-exports must not form cycles".into()),
                ..DiagnosticDetails::default()
            },
            Self::ImportTargetUsesImport { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this import target starts with another import alias"
                )]
                .into(),
                help: Some(
                    "imports are resolved independently; use the original global path instead of \
                     another import alias"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::SelfReferentialImport { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this import resolves to the module that contains it"
                )]
                .into(),
                help: Some(
                    "a module cannot import itself; reference local items directly or use \
                     absolute paths in code"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::ImportTargetIsLocalSubmodule { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this import resolves to a submodule declared in the same scope"
                )]
                .into(),
                help: Some(
                    "reference the submodule directly with a submodule-qualified path instead of \
                     importing it"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidRelativePath { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this path does not start with a local item, import, or submodule"
                )]
                .into(),
                help: Some(
                    "item paths must be absolute, local, or qualified by an import or submodule \
                     in the current module"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::UndefinedSymbol { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "you might be missing an import, or the containing library has not been linked"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidSysCallTarget { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "call occurs here")].into(),
                ..DiagnosticDetails::default()
            },
            Self::KernelProcNotSyscall { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "non-syscall reference to kernel procedure")]
                    .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidInvokeTarget { span, source_file, path } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    format!("this path resolves to {path}, which is not a procedure")
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::AdviceMapKeyAlreadyPresent { prev_values, new_values, .. } => DiagnosticDetails {
                help: Some(
                    format!(
                        "previous values at key were '{prev_values:?}'. Operation would have \
                         replaced them with '{new_values:?}'"
                    )
                    .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::RecursiveType { span, cycle_span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![
                    Label::new(*span, "this type is defined in terms of itself"),
                    Label::new(*cycle_span, "the cycle returns here")
                ]
                .into(),
                help: Some(
                    "this type refers to itself without an intervening pointer, so it would have \
                     infinite size; introduce a pointer somewhere in the cycle"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidTypeRef { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("the item this path resolves to is not a type definition".into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidConstantRef { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("the item this path resolves to is not a constant definition".into()),
                ..DiagnosticDetails::default()
            },
            _ => DiagnosticDetails::default(),
        }
    }
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
