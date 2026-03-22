pub mod diagnostics;
pub mod lexer;
pub mod parser;
pub mod syntax;

pub use miden_utils_diagnostics::{self as diagnostics, Report};
pub use rowan;

pub use self::{
    diagnostics::Diagnostic,
    lexer::{Lexer, Token, tokenize},
    parser::{Parse, parse_text},
    syntax::{MasmLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken},
};

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
