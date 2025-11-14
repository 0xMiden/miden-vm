// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, ops::Range};

use miden_debug_types::{SourceId, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, miette};

use super::ParseError;

// LITERAL ERROR KIND
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LiteralErrorKind {
    /// The input was empty
    Empty,
    /// The input contained an invalid digit
    InvalidDigit,
    /// The value overflows `u32::MAX`
    U32Overflow,
    /// The value overflows `Felt::MODULUS`
    FeltOverflow,
    /// The value was expected to be a value < 63
    InvalidBitSize,
}

impl fmt::Display for LiteralErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("input was empty"),
            Self::InvalidDigit => f.write_str("invalid digit"),
            Self::U32Overflow => f.write_str("value overflowed the u32 range"),
            Self::FeltOverflow => f.write_str("value overflowed the field modulus"),
            Self::InvalidBitSize => {
                f.write_str("expected value to be a valid bit size, e.g. 0..63")
            },
        }
    }
}

// HEX ERROR KIND
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HexErrorKind {
    /// Expected two hex digits for every byte, but had fewer than that
    MissingDigits,
    /// Valid hex-encoded integers are expected to come in sizes of 8, 16, or 64 digits,
    /// but the input consisted of an invalid number of digits.
    Invalid,
    /// Occurs when a hex-encoded value overflows `Felt::MODULUS`, the maximum integral value
    Overflow,
    /// Occurs when the hex-encoded value is > 64 digits
    TooLong,
}

impl fmt::Display for HexErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingDigits => {
                f.write_str("expected number of hex digits to be a multiple of 2")
            },
            Self::Invalid => f.write_str("expected 2, 4, 8, 16, or 64 hex digits"),
            Self::Overflow => f.write_str("value overflowed the field modulus"),
            Self::TooLong => f.write_str(
                "value has too many digits, long hex strings must contain exactly 64 digits",
            ),
        }
    }
}

// BINARY ERROR KIND
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BinErrorKind {
    /// Occurs when the bin-encoded value is > 32 digits
    TooLong,
}

impl fmt::Display for BinErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str(
                "value has too many digits, binary string can contain no more than 32 digits",
            ),
        }
    }
}

// PARSING ERROR
// ================================================================================================

#[derive(Debug, Default, thiserror::Error, Diagnostic)]
#[repr(u8)]
pub enum ParsingError {
    #[default]
    #[error("parsing failed due to unexpected input")]
    #[diagnostic()]
    Failed = 0,
    #[error("expected input to be valid utf8, but invalid byte sequences were found")]
    #[diagnostic()]
    InvalidUtf8 {
        #[label("invalid byte sequence starts here")]
        span: SourceSpan,
    },
    #[error(
        "expected input to be valid utf8, but end-of-file was reached before final codepoint was read"
    )]
    #[diagnostic()]
    IncompleteUtf8 {
        #[label("the codepoint starting here is incomplete")]
        span: SourceSpan,
    },
    #[error("invalid syntax")]
    #[diagnostic()]
    InvalidToken {
        #[label("occurs here")]
        span: SourceSpan,
    },
    #[error("invalid syntax")]
    #[diagnostic(help("expected {}", expected.as_slice().join(", or ")))]
    UnrecognizedToken {
        #[label("found a {token} here")]
        span: SourceSpan,
        token: String,
        expected: Vec<String>,
    },
    #[error("unexpected trailing tokens")]
    #[diagnostic()]
    ExtraToken {
        #[label("{token} was found here, but was not expected")]
        span: SourceSpan,
        token: String,
    },
    #[error("unexpected end of file")]
    #[diagnostic(help("expected {}", expected.as_slice().join(", or ")))]
    UnrecognizedEof {
        #[label("reached end of file here")]
        span: SourceSpan,
        expected: Vec<String>,
    },
    #[error("{error}")]
    #[diagnostic(help(
        "bare identifiers must be lowercase alphanumeric with '_', quoted identifiers can include any graphical character"
    ))]
    InvalidIdentifier {
        #[source]
        #[diagnostic(source)]
        error: crate::ast::IdentError,
        #[label]
        span: SourceSpan,
    },
    #[error("unclosed quoted identifier")]
    #[diagnostic()]
    UnclosedQuote {
        #[label("no match for quotation mark starting here")]
        start: SourceSpan,
    },
    #[error("too many instructions in a single code block")]
    #[diagnostic()]
    CodeBlockTooBig {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid constant expression: division by zero")]
    DivisionByZero {
        #[label]
        span: SourceSpan,
    },
    #[error("unexpected string in an arithmetic expression")]
    #[diagnostic()]
    StringInArithmeticExpression {
        #[label]
        span: SourceSpan,
    },
    #[error("doc comment is too large")]
    #[diagnostic(help("make sure it is less than u16::MAX bytes in length"))]
    DocsTooLarge {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid literal: {}", kind)]
    #[diagnostic()]
    InvalidLiteral {
        #[label]
        span: SourceSpan,
        kind: LiteralErrorKind,
    },
    #[error("invalid literal: {}", kind)]
    #[diagnostic()]
    InvalidHexLiteral {
        #[label]
        span: SourceSpan,
        kind: HexErrorKind,
    },
    #[error("invalid literal: {}", kind)]
    #[diagnostic()]
    InvalidBinaryLiteral {
        #[label]
        span: SourceSpan,
        kind: BinErrorKind,
    },
    #[error("invalid MAST root literal")]
    InvalidMastRoot {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid library path: {}", message)]
    InvalidLibraryPath {
        #[label]
        span: SourceSpan,
        message: String,
    },
    #[error("invalid immediate: value must be in the range {}..{} (exclusive)", range.start, range.end)]
    ImmediateOutOfRange {
        #[label]
        span: SourceSpan,
        range: Range<usize>,
    },
    #[error("too many procedures in this module")]
    #[diagnostic()]
    ModuleTooLarge {
        #[label]
        span: SourceSpan,
    },
    #[error("too many re-exported procedures in this module")]
    #[diagnostic()]
    ModuleTooManyReexports {
        #[label]
        span: SourceSpan,
    },
    #[error(
        "too many operands for `push`: tried to push {} elements, but only 16 can be pushed at one time",
        count
    )]
    #[diagnostic()]
    PushOverflow {
        #[label]
        span: SourceSpan,
        count: usize,
    },
    #[error("expected a fully-qualified module path, e.g. `std::u64`")]
    UnqualifiedImport {
        #[label]
        span: SourceSpan,
    },
    #[error(
        "re-exporting a procedure identified by digest requires giving it a name, e.g. `pub use DIGEST->foo`"
    )]
    UnnamedReexportOfMastRoot {
        #[label]
        span: SourceSpan,
    },
    #[error("conflicting attributes for procedure definition")]
    #[diagnostic()]
    AttributeConflict {
        #[label(
            "conflict occurs because an attribute with the same name has already been defined"
        )]
        span: SourceSpan,
        #[label("previously defined here")]
        prev: SourceSpan,
    },
    #[error("conflicting key-value attributes for procedure definition")]
    #[diagnostic()]
    AttributeKeyValueConflict {
        #[label(
            "conflict occurs because a key with the same name has already been set in a previous declaration"
        )]
        span: SourceSpan,
        #[label("previously defined here")]
        prev: SourceSpan,
    },
    #[error("invalid Advice Map key")]
    #[diagnostic()]
    InvalidAdvMapKey {
        #[label(
            "an Advice Map key must be a word, either in 64-character hex format or in array-like format `[f0,f1,f2,f3]`"
        )]
        span: SourceSpan,
    },
    #[error("invalid slice constant")]
    #[diagnostic()]
    InvalidSliceConstant {
        #[label("slices are only supported over word-sized constants")]
        span: SourceSpan,
    },
    #[error("invalid slice: expected valid range")]
    #[diagnostic()]
    InvalidRange {
        #[label("range used for the word constant slice is malformed: `{range:?}`")]
        span: SourceSpan,
        range: Range<usize>,
    },
    #[error("invalid slice: expected non-empty range")]
    #[diagnostic()]
    EmptySlice {
        #[label("range used for the word constant slice is empty: `{range:?}`")]
        span: SourceSpan,
        range: Range<usize>,
    },
    #[error("unrecognized calling convention")]
    #[diagnostic(help("expected one of: 'fast', 'C', 'wasm', 'canon-lift', or 'canon-lower'"))]
    UnrecognizedCallConv {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid struct annotation")]
    #[diagnostic(help("expected one of: '@packed', '@transparent', '@bigendian', or '@align(N)'"))]
    InvalidStructAnnotation {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid struct representation")]
    #[diagnostic()]
    InvalidStructRepr {
        #[label("{message}")]
        span: SourceSpan,
        message: String,
    },
    #[error("deprecated instruction: `{instruction}` has been removed")]
    #[diagnostic(help("use `{}` instead", replacement))]
    DeprecatedInstruction {
        #[label("this instruction is no longer supported")]
        span: SourceSpan,
        instruction: String,
        replacement: String,
    },
    #[error("invalid procedure @locals attribute")]
    #[diagnostic()]
    InvalidLocalsAttr {
        #[label("{message}")]
        span: SourceSpan,
        message: String,
    },
}

impl ParsingError {
    fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *<*const _>::from(self).cast::<u8>() }
    }
}

impl Eq for ParsingError {}

impl PartialEq for ParsingError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Failed, Self::Failed) => true,
            (Self::InvalidLiteral { kind: l, .. }, Self::InvalidLiteral { kind: r, .. }) => l == r,
            (Self::InvalidHexLiteral { kind: l, .. }, Self::InvalidHexLiteral { kind: r, .. }) => {
                l == r
            },
            (
                Self::InvalidLibraryPath { message: l, .. },
                Self::InvalidLibraryPath { message: r, .. },
            ) => l == r,
            (
                Self::ImmediateOutOfRange { range: l, .. },
                Self::ImmediateOutOfRange { range: r, .. },
            ) => l == r,
            (Self::PushOverflow { count: l, .. }, Self::PushOverflow { count: r, .. }) => l == r,
            (
                Self::UnrecognizedToken { token: ltok, expected: lexpect, .. },
                Self::UnrecognizedToken { token: rtok, expected: rexpect, .. },
            ) => ltok == rtok && lexpect == rexpect,
            (Self::ExtraToken { token: ltok, .. }, Self::ExtraToken { token: rtok, .. }) => {
                ltok == rtok
            },
            (
                Self::UnrecognizedEof { expected: lexpect, .. },
                Self::UnrecognizedEof { expected: rexpect, .. },
            ) => lexpect == rexpect,
            (x, y) => x.tag() == y.tag(),
        }
    }
}

impl ParsingError {
    pub fn from_utf8_error(source_id: SourceId, err: core::str::Utf8Error) -> Self {
        let start = u32::try_from(err.valid_up_to()).ok().unwrap_or(u32::MAX);
        match err.error_len() {
            None => Self::IncompleteUtf8 { span: SourceSpan::at(source_id, start) },
            Some(len) => Self::InvalidUtf8 {
                span: SourceSpan::new(source_id, start..(start + len as u32)),
            },
        }
    }

    pub fn from_parse_error(source_id: SourceId, err: ParseError<'_>) -> Self {
        use super::Token;

        match err {
            ParseError::InvalidToken { location: at } => {
                Self::InvalidToken { span: SourceSpan::at(source_id, at) }
            },
            ParseError::UnrecognizedToken { token: (l, Token::Eof, r), expected } => {
                Self::UnrecognizedEof {
                    span: SourceSpan::new(source_id, l..r),
                    expected: simplify_expected_tokens(expected),
                }
            },
            ParseError::UnrecognizedToken { token: (l, tok, r), expected } => {
                Self::UnrecognizedToken {
                    span: SourceSpan::new(source_id, l..r),
                    token: tok.to_string(),
                    expected: simplify_expected_tokens(expected),
                }
            },
            ParseError::ExtraToken { token: (l, tok, r) } => Self::ExtraToken {
                span: SourceSpan::new(source_id, l..r),
                token: tok.to_string(),
            },
            ParseError::UnrecognizedEof { location: at, expected } => Self::UnrecognizedEof {
                span: SourceSpan::new(source_id, at..at),
                expected: simplify_expected_tokens(expected),
            },
            ParseError::User { error } => error,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

// The parser generator will show every token that is expected in some scenarios, so to avoid
// cluttering the diagnostic output with all of the instruction opcodes, we collapse them into a
// single token.
fn simplify_expected_tokens(expected: Vec<String>) -> Vec<String> {
    use super::Token;
    let mut has_instruction = false;
    let mut has_ctrl = false;
    let mut has_type = false;
    expected
        .into_iter()
        .filter_map(|t| {
            let tok = match t.as_str() {
                "bare_ident" => return Some("identifier".to_string()),
                "const_ident" => return Some("constant identifier".to_string()),
                "quoted_ident" => return Some("quoted identifier".to_string()),
                "doc_comment" => return Some("doc comment".to_string()),
                "hex_value" => return Some("hex-encoded literal".to_string()),
                "bin_value" => return Some("bin-encoded literal".to_string()),
                "uint" => return Some("integer literal".to_string()),
                "EOF" => return Some("end of file".to_string()),
                other => other[1..].strip_suffix('"').and_then(Token::parse),
            };
            match tok {
                Some(Token::If | Token::While | Token::Repeat) => {
                    if !has_ctrl {
                        has_ctrl = true;
                        Some("control flow opcode (e.g. \"if.true\")".to_string())
                    } else {
                        None
                    }
                },
                Some(tok) if tok.is_instruction() => {
                    if !has_instruction {
                        has_instruction = true;
                        Some("primitive opcode (e.g. \"add\")".to_string())
                    } else {
                        None
                    }
                },
                Some(tok) if tok.is_type_keyword() => {
                    if !has_type {
                        has_type = true;
                        Some("type (e.g. \"felt\")".to_string())
                    } else {
                        None
                    }
                },
                _ => Some(t),
            }
        })
        .collect()
}
