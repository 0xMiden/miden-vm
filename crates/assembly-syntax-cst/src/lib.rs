//! Lossless concrete syntax support for Miden Assembly.
//!
//! This crate provides a trivia-preserving lexer, a rowan-based concrete syntax tree, and a small
//! set of typed AST wrappers over that CST. The primary entry point for production use is
//! [`parse_source_file`], which accepts an [`Arc<SourceFile>`][miden_debug_types::SourceFile] and
//! retains source/span information for both diagnostics and downstream lowering.

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod syntax;

pub use miden_utils_diagnostics::{self as diagnostics, Report};
pub use rowan;

pub use self::{
    ast::{Item, Operation},
    lexer::{Lexer, Token, tokenize, tokenize_text},
    parser::{Parse, parse_source_file, parse_text},
    syntax::{MasmLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken},
};

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
