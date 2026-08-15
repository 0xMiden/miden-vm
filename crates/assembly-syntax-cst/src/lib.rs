//! Lossless concrete syntax support for Miden Assembly.
//!
//! This crate provides a trivia-preserving lexer, a rowan-based concrete syntax tree, and a small
//! set of typed AST wrappers over that CST. The primary entry point for production use is
//! [`parse`], which accepts a source identity and text and returns an [`Outcome`] containing both
//! the recovered tree and any diagnostics emitted while parsing. Source text is owned by the
//! caller's source provider; the tree retains only source/span provenance for downstream lowering.
#![no_std]

#[cfg(any(test, feature = "std"))]
#[cfg_attr(test, macro_use)]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod syntax;

pub use miden_diagnostics::{self as diagnostics, Outcome, Report};
pub use rowan;

pub use self::{
    ast::{Item, Operation},
    lexer::{Lexer, Token, tokenize},
    parser::{Parse, ParseOutcome, parse, parse_inline_masm},
    syntax::{MasmLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken},
};

/// Maximum allowed nesting of control-flow blocks.
///
/// This limit prevents stack overflows while parsing or compiling maliciously deep block nesting,
/// while remaining far above typical program structure depth.
pub const MAX_CONTROL_FLOW_NESTING: usize = 256;
