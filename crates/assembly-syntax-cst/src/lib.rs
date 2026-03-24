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
