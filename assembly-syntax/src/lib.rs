#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{Felt, FieldElement, StarkField, Word, prettier, utils::DisplayHex};
pub use miden_debuginfo as debuginfo;
pub use miden_utils_diagnostics::{self as diagnostics, Report};

pub mod ast;
pub mod library;
mod parse;
pub mod parser;
mod sema;
pub mod testing;

#[doc(hidden)]
pub use self::{
    library::{
        KernelLibrary, Library, LibraryError, LibraryNamespace, LibraryPath, LibraryPathComponent,
        PathError, Version, VersionError,
    },
    parser::{ModuleParser, ParsingError},
};
pub use self::{
    parse::{Parse, ParseOptions},
    sema::SemanticAnalysisError,
};
