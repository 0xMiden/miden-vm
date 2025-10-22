// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use miden_core::errors::KernelError;

use crate::{
    ast::QualifiedProcedureName,
    diagnostics::{Diagnostic, miette},
};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum LibraryError {
    #[error("library must contain at least one exported procedure")]
    #[diagnostic()]
    NoExport,
    #[error("invalid export in kernel library: {procedure_path}")]
    InvalidKernelExport { procedure_path: QualifiedProcedureName },
    // Technically KernelError is the source error here, but since LibraryError is sometimes
    // converted into a Report and that doesn't implement core::error::Error, treating
    // KernelError as a source error would effectively swallow it, so we include it in the
    // error message instead.
    #[error("failed to convert library into kernel library: {0}")]
    KernelConversion(KernelError),
    #[error("invalid export: no procedure root for {procedure_path} procedure")]
    NoProcedureRootForExport { procedure_path: QualifiedProcedureName },
}
