use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt;

use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, DiagnosticDetails, Label, Severity};

use crate::{
    Path,
    ast::{SymbolResolutionError, constants::ConstEvalError},
};

/// The high-level error type for all semantic analysis errors.
///
/// This rolls up multiple errors into a single one, and as such, can emit many
/// diagnostics at once. You should prefer to gather up errors and continue with
/// analysis for as long as possible before returning an error of this type, so
/// as to provide as much information to the user as possible, but there are cases
/// where doing so would not be profitable - it is a judgement call.
///
/// The semantic analyzer does this though, and you can examine its implementation
/// to see how we approach this during the semantic analysis phase specifically.
#[derive(Debug, thiserror::Error)]
#[error("syntax error")]
pub struct SyntaxError {
    pub source_file: Arc<SourceFile>,
    pub errors: Vec<SemanticAnalysisError>,
}

impl Diagnostic for SyntaxError {
    fn details(&self) -> DiagnosticDetails<'_> {
        DiagnosticDetails {
            source: Some(&self.source_file),
            help: Some("see emitted diagnostics for details".into()),
            related: self.errors.iter().map(|error| error as &dyn Diagnostic).collect(),
            ..DiagnosticDetails::default()
        }
    }
}

/// This type is used when emitting advice/warnings, when those are not being treated as errors.
///
/// Like [SyntaxError], this rolls up all such notices into a single batch, and emits them all
/// at once. The difference is that we never return this as an error from any API, it simply
/// exists to leverage the diagnostic renderer.
#[derive(Debug, thiserror::Error)]
#[error("one or more warnings were emitted")]
#[cfg_attr(not(feature = "std"), expect(unused))]
pub struct SyntaxWarning {
    pub source_file: Arc<SourceFile>,
    pub errors: Vec<SemanticAnalysisError>,
}

impl Diagnostic for SyntaxWarning {
    fn details(&self) -> DiagnosticDetails<'_> {
        DiagnosticDetails {
            source: Some(&self.source_file),
            help: Some("see below for details".into()),
            related: self.errors.iter().map(|error| error as &dyn Diagnostic).collect(),
            ..DiagnosticDetails::default()
        }
    }
}

/// Identifies the exported surface where a private type was found.
#[derive(Clone, Copy)]
pub enum ExportedTypeUse {
    ProcedureSignature,
    TypeDeclaration,
}

impl ExportedTypeUse {
    pub fn private_type_error(
        self,
        span: SourceSpan,
        defined: SourceSpan,
    ) -> SemanticAnalysisError {
        match self {
            Self::ProcedureSignature => {
                SemanticAnalysisError::PrivateTypeInExportedSignature { span, defined }
            },
            Self::TypeDeclaration => {
                SemanticAnalysisError::PrivateTypeInExportedType { span, defined }
            },
        }
    }
}

/// Represents an error that occurs during semantic analysis
#[derive(Debug, thiserror::Error)]
pub enum SemanticAnalysisError {
    #[error(
        "conflicting module namespace specification: expected '{expected}', but got '{actual}'"
    )]
    NamespaceConflict {
        expected: Arc<Path>,
        actual: Arc<Path>,
        span: SourceSpan,
    },
    #[error("invalid namespace '{path}': {err}")]
    InvalidNamespacePath { path: Arc<Path>, err: crate::PathError },
    #[error("invalid namespace declaration: must be placed before any other item in the module")]
    MisplacedNamespaceDeclaration { span: SourceSpan },
    #[error("invalid module: no namespace declared or explicitly provided")]
    MissingNamespace,
    #[error("invalid program: no entrypoint defined")]
    MissingEntrypoint,
    #[error("invalid module: unexpected entrypoint definition")]
    UnexpectedEntrypoint { span: SourceSpan },
    #[error("invalid module: multiple conflicting entrypoints defined")]
    MultipleEntrypoints { span: SourceSpan, prev_span: SourceSpan },
    #[error("invalid invocation target")]
    InvalidInvokePath { span: SourceSpan },
    #[error("invalid program: procedure exports are not allowed")]
    UnexpectedExport { span: SourceSpan },
    #[error("invalid enum type representation: underlying type must be an integral or felt type")]
    InvalidEnumRepr { span: SourceSpan },
    #[error("invalid enum discriminant: value is not a valid instance of the {repr} type")]
    InvalidEnumDiscriminant {
        span: SourceSpan,
        repr: crate::ast::types::Type,
    },
    #[error("invalid enum discriminant: value conflicts with another variant of the same enum")]
    EnumDiscriminantConflict { span: SourceSpan, prev: SourceSpan },
    #[error("symbol conflict: found duplicate definitions of the same name")]
    SymbolConflict { span: SourceSpan, prev_span: SourceSpan },
    #[error("dependency conflict: found duplicate 'extern package' declarations")]
    ExternPackageConflict { span: SourceSpan, prev_span: SourceSpan },
    #[error("private type in exported procedure signature")]
    PrivateTypeInExportedSignature { span: SourceSpan, defined: SourceSpan },
    #[error("private type in exported type declaration")]
    PrivateTypeInExportedType { span: SourceSpan, defined: SourceSpan },
    #[error("unused import")]
    UnusedImport { span: SourceSpan },
    #[error("unused constant")]
    UnusedConstant { span: SourceSpan },
    #[error("missing import: the referenced module has not been imported")]
    MissingImport { span: SourceSpan },
    #[error("symbol conflict: import would shadow a previous import of the same name")]
    ImportConflict { span: SourceSpan, prev_span: SourceSpan },
    #[error("invalid re-exported module: you may only re-export items")]
    ReexportedModule { span: SourceSpan },
    #[error("invalid re-export target: kernel procedures may not be re-exported")]
    ReexportedKernelProcedure { span: SourceSpan },
    #[error(
        "invalid re-exported procedure: kernel modules may not re-export procedures from other modules"
    )]
    ReexportFromKernel { span: SourceSpan },
    #[error("invalid syscall: callee must be resolvable to kernel module")]
    InvalidSyscallTarget { span: SourceSpan },
    #[error("invalid procedure path: not an item")]
    InvalidInvokeTargetViaImport { span: SourceSpan, import: SourceSpan },
    #[error("invalid recursive procedure call")]
    InvalidRecursiveCall { span: SourceSpan },
    #[error("invalid recursive procedure call")]
    SelfRecursive { span: SourceSpan },
    #[error("invalid repeat count")]
    InvalidRepeatCount { span: SourceSpan, min: u32, max: u32 },
    #[error("invalid immediate: value is larger than expected range")]
    ImmediateOverflow { span: SourceSpan },
    #[error("invalid module: {}", kind)]
    LimitExceeded { span: SourceSpan, kind: LimitKind },
    #[error("unused docstring")]
    UnusedDocstring { span: SourceSpan },
    #[error("unused docstring")]
    TrailingDocstring { span: SourceSpan },
    #[error("unused docstring")]
    ImportDocstring { span: SourceSpan },
    #[error("advmap key already defined")]
    AdvMapKeyAlreadyDefined { span: SourceSpan },
    #[error(transparent)]
    ConstEvalError(#[from] ConstEvalError),
    #[error(transparent)]
    SymbolResolutionError(#[from] Box<SymbolResolutionError>),
}

impl Diagnostic for SemanticAnalysisError {
    fn severity(&self) -> Severity {
        match self {
            Self::UnusedImport { .. }
            | Self::UnusedConstant { .. }
            | Self::UnusedDocstring { .. }
            | Self::TrailingDocstring { .. }
            | Self::ImportDocstring { .. } => Severity::Warning,
            _ => Severity::Error,
        }
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::NamespaceConflict { span, .. } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "this declaration conflicts with the expected namespace"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::MisplacedNamespaceDeclaration { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "make sure this declaration precedes other declarations in this module"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::MissingNamespace => DiagnosticDetails {
                help: Some(
                    "ensure you declare this module's namespace with a `namespace` declaration, \
                     or by providing it to the parser"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::MissingEntrypoint => DiagnosticDetails {
                help: Some(
                    "ensure you define an entrypoint somewhere in the body with `begin`..`end`"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::UnexpectedEntrypoint { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("library modules cannot contain `begin`..`end` blocks".into()),
                ..DiagnosticDetails::default()
            },
            Self::MultipleEntrypoints { span, prev_span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span), Label::underline(*prev_span)].into(),
                help: Some(
                    "an executable module can only have a single `begin`..`end` block".into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidInvokePath { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("path contains an invalid component".into()),
                ..DiagnosticDetails::default()
            },
            Self::UnexpectedExport { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("perhaps you meant to use `proc` instead of `export`?".into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidEnumRepr { span }
            | Self::InvalidEnumDiscriminant { span, .. }
            | Self::ReexportedModule { span }
            | Self::ReexportedKernelProcedure { span }
            | Self::ReexportFromKernel { span }
            | Self::InvalidSyscallTarget { span }
            | Self::ImmediateOverflow { span }
            | Self::AdvMapKeyAlreadyDefined { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                ..DiagnosticDetails::default()
            },
            Self::EnumDiscriminantConflict { span, prev } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(*span, "this discriminant value conflicts with a previous variant"),
                    Label::new(*prev, "discriminant previously observed here")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::SymbolConflict { span, prev_span }
            | Self::ExternPackageConflict { span, prev_span } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(*span, "conflict occurs here"),
                    Label::new(*prev_span, "previously defined here")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::PrivateTypeInExportedSignature { span, defined } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(
                        *span,
                        "this exported procedure signature references a private type"
                    ),
                    Label::new(*defined, "this type is private")
                ]
                .into(),
                help: Some(
                    "exported procedure signatures may only reference public types, including \
                     nested type dependencies"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::PrivateTypeInExportedType { span, defined } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(*span, "this exported type declaration references a private type"),
                    Label::new(*defined, "this type is private")
                ]
                .into(),
                help: Some(
                    "exported type declarations may only reference public types, including nested \
                     type dependencies"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::UnusedImport { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("this import is never used and can be safely removed".into()),
                ..DiagnosticDetails::default()
            },
            Self::UnusedConstant { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("this constant is never used and can be safely removed".into()),
                ..DiagnosticDetails::default()
            },
            Self::MissingImport { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "this reference is invalid without a corresponding import"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::ImportConflict { span, prev_span } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(*span, "caused by this import"),
                    Label::new(*prev_span, "previously imported here")
                ]
                .into(),
                help: Some(
                    "imports must have unique names within a module, try aliasing one of the \
                     imports if both are needed"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidInvokeTargetViaImport { span, import } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(*span, "call occurs here"),
                    Label::new(
                        *import,
                        "expected this to resolve to a module, but got a module item"
                    )
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidRecursiveCall { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "caused by this call")].into(),
                help: Some(
                    "this call induces a cycle that returns back to the caller, you must break \
                     that cycle"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::SelfRecursive { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("this call is self-recursive, which is not allowed".into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidRepeatCount { span, min, max } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(format!("repeat count must be in the range {min}..={max}").into()),
                ..DiagnosticDetails::default()
            },
            Self::LimitExceeded { span, .. } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("try breaking this module up into submodules".into()),
                ..DiagnosticDetails::default()
            },
            Self::UnusedDocstring { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "this docstring is immediately followed by at least one empty line, then \
                     another docstring, if you intended these to be a single docstring, you \
                     should remove the empty lines"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::TrailingDocstring { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("trailing docstrings are useless".into()),
                ..DiagnosticDetails::default()
            },
            Self::ImportDocstring { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "imports and re-exports cannot have docstrings, you should use line comment \
                     syntax here instead"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::ConstEvalError(error) => error.details(),
            Self::SymbolResolutionError(error) => error.details(),
            _ => DiagnosticDetails::default(),
        }
    }
}

impl From<SymbolResolutionError> for SemanticAnalysisError {
    fn from(value: SymbolResolutionError) -> Self {
        Self::SymbolResolutionError(Box::new(value))
    }
}

/// Represents a system limit that was exceeded
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LimitKind {
    /// The total number of items in a module
    Items,
    /// The total number of procedures in a module
    Procedures,
    /// The total number of procedure locals
    Locals,
    /// The total number of imports in a module
    Imports,
    /// The total number of calls to imports
    ///
    /// TODO(pauls): Is this even a limit anymore?
    CalledImports,
    /// The total number of instructions in a procedure.
    Instructions,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Items => f.write_str("too many items in module"),
            Self::Procedures => f.write_str("too many procedures in module"),
            Self::Locals => f.write_str("too many procedure locals"),
            Self::Imports => f.write_str("too many imported procedures"),
            Self::CalledImports => f.write_str("too many calls to imported procedures"),
            Self::Instructions => f.write_str("too many instructions in block"),
        }
    }
}
