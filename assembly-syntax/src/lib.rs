#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{Felt, FieldElement, StarkField, Word, prettier, utils::DisplayHex};

pub mod ast;
pub mod library;
mod parse;
pub mod parser;
mod sema;
pub mod testing;

pub mod diagnostics {
    pub use miden_core_diagnostics::{
        debuginfo::{
            DefaultSourceManager, SourceContent, SourceFile, SourceId, SourceLanguage,
            SourceManager, SourceSpan, Span, Spanned, Uri,
        },
        *,
    };
}

pub use miden_core_diagnostics::{
    Report,
    debuginfo::{DefaultSourceManager, SourceFile, SourceManager, SourceSpan, Span, Spanned},
    report,
};

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
