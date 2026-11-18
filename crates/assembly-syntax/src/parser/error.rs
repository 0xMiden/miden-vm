use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt, ops::Range};

use miden_debug_types::SourceSpan;
use miden_utils_diagnostics::{Diagnostic, DiagnosticDetails, Label};

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
    /// The value overflows `Felt::ORDER_U64`
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
    /// Occurs when a hex-encoded value overflows `Felt::ORDER_U64`, the maximum integral value
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

#[non_exhaustive]
#[derive(Debug, Default, thiserror::Error)]
#[repr(u8)]
pub enum ParsingError {
    #[default]
    #[error("parsing failed due to unexpected input")]
    Failed = 0,
    #[error("expected input to be valid utf8, but invalid byte sequences were found")]
    InvalidUtf8 { span: SourceSpan },
    #[error(
        "expected input to be valid utf8, but end-of-file was reached before final codepoint was read"
    )]
    IncompleteUtf8 { span: SourceSpan },
    #[error("invalid syntax")]
    InvalidToken { span: SourceSpan },
    #[error("invalid syntax: {message}")]
    InvalidSyntax { span: SourceSpan, message: String },
    #[error("invalid syntax")]
    UnrecognizedToken {
        span: SourceSpan,
        token: String,
        expected: Vec<String>,
    },
    #[error("unexpected trailing tokens")]
    ExtraToken { span: SourceSpan, token: String },
    #[error("unexpected end of file")]
    UnrecognizedEof { span: SourceSpan, expected: Vec<String> },
    #[error("{error}")]
    InvalidIdentifier {
        #[source]
        error: crate::ast::IdentError,
        span: SourceSpan,
    },
    #[error("unclosed quoted identifier")]
    UnclosedQuote { start: SourceSpan },
    #[error("too many instructions in a single code block")]
    CodeBlockTooBig { span: SourceSpan },
    #[error("control-flow nesting depth exceeded")]
    ControlFlowNestingDepthExceeded { span: SourceSpan, max_depth: usize },
    #[error("constant expression nesting depth exceeded")]
    ConstantExpressionNestingDepthExceeded { span: SourceSpan, max_depth: usize },
    #[error("type expression nesting depth exceeded")]
    TypeExpressionNestingDepthExceeded { span: SourceSpan, max_depth: usize },
    #[error("invalid constant expression: division by zero")]
    DivisionByZero { span: SourceSpan },
    #[error("doc comment is too large")]
    DocsTooLarge { span: SourceSpan },
    #[error("invalid literal: {}", kind)]
    InvalidLiteral { span: SourceSpan, kind: LiteralErrorKind },
    #[error("invalid literal: {}", kind)]
    InvalidHexLiteral { span: SourceSpan, kind: HexErrorKind },
    #[error("invalid literal: {}", kind)]
    InvalidBinaryLiteral { span: SourceSpan, kind: BinErrorKind },
    #[error("invalid MAST root literal")]
    InvalidMastRoot { span: SourceSpan },
    #[error("invalid library path: {}", message)]
    InvalidLibraryPath { span: SourceSpan, message: String },
    #[error("invalid immediate: value must be in the range {}..{} (exclusive)", range.start, range.end)]
    ImmediateOutOfRange { span: SourceSpan, range: Range<usize> },
    #[error("too many procedures in this module")]
    ModuleTooLarge { span: SourceSpan },
    #[error("too many re-exported procedures in this module")]
    ModuleTooManyReexports { span: SourceSpan },
    #[error(
        "too many operands for `push`: tried to push {} elements, but only 16 can be pushed at one time",
        count
    )]
    PushOverflow { span: SourceSpan, count: usize },
    #[error("expected a fully-qualified module path, e.g. `std::u64`")]
    UnqualifiedImport { span: SourceSpan },
    #[error(
        "source-level digest re-exports are not supported; re-export a named item with `pub use {{item}} from module`"
    )]
    UnnamedReexportOfMastRoot { span: SourceSpan },
    #[error("conflicting attributes for procedure definition")]
    AttributeConflict { span: SourceSpan, prev: SourceSpan },
    #[error("conflicting key-value attributes for procedure definition")]
    AttributeKeyValueConflict { span: SourceSpan, prev: SourceSpan },
    #[error("invalid Advice Map key")]
    InvalidAdvMapKey { span: SourceSpan },
    #[error("invalid slice constant")]
    InvalidSliceConstant { span: SourceSpan },
    #[error("invalid slice: expected valid range")]
    InvalidRange { span: SourceSpan, range: Range<usize> },
    #[error("invalid slice: expected non-empty range")]
    EmptySlice { span: SourceSpan, range: Range<usize> },
    #[error("unrecognized calling convention")]
    UnrecognizedCallConv { span: SourceSpan },
    #[error("invalid struct annotation")]
    InvalidStructAnnotation { span: SourceSpan },
    #[error("invalid struct representation")]
    InvalidStructRepr { span: SourceSpan, message: String },
    #[error("deprecated instruction: `{instruction}` has been removed")]
    DeprecatedInstruction {
        span: SourceSpan,
        instruction: String,
        replacement: String,
    },
    #[error("invalid procedure @locals attribute")]
    InvalidLocalsAttr { span: SourceSpan, message: String },
    #[error("invalid padding value for the `adv.push_mapvaln` instruction: {padding}")]
    InvalidPadValue { span: SourceSpan, padding: u8 },
    #[error(
        "invalid submodule declaration '{name}': could not find module sources at '{directory}/{basename}.masm' or '{directory}/{basename}/mod.masm'"
    )]
    UndefinedSubmodule {
        name: crate::ast::Ident,
        basename: alloc::boxed::Box<str>,
        directory: miden_debug_types::Uri,
        span: SourceSpan,
        source_file: Option<Arc<miden_debug_types::SourceFile>>,
    },
    #[error(
        "invalid submodule declaration '{name}': submodules must not have the same name as their parent"
    )]
    SelfReferentialSubmodule {
        name: crate::ast::Ident,
        parent_module_uri: miden_debug_types::Uri,
        span: SourceSpan,
        source_file: Option<Arc<miden_debug_types::SourceFile>>,
    },
    #[error(
        "conflicting submodule paths detected: '{name}' can be parsed from either '{first}' and '{second}', but not both"
    )]
    AmbiguousSubmoduleLocation {
        name: crate::ast::Ident,
        first: miden_debug_types::Uri,
        second: miden_debug_types::Uri,
        span: SourceSpan,
        source_file: Option<Arc<miden_debug_types::SourceFile>>,
    },
    #[error(
        "invalid submodule declaration '{name}': module source '{module_uri}' is already reachable through another submodule declaration"
    )]
    DuplicateSubmoduleSource {
        name: crate::ast::Ident,
        module_uri: miden_debug_types::Uri,
        span: SourceSpan,
        source_file: Option<Arc<miden_debug_types::SourceFile>>,
    },
    #[error("conflicting attributes for procedure definition")]
    CallConvAttributeConflict {
        cc_span: SourceSpan,
        attr_span: SourceSpan,
    },
    #[error("conflicting attributes for procedure definition")]
    ConflictingProtocolAbiAttribute { span: SourceSpan, prev: SourceSpan },
}

impl Diagnostic for ParsingError {
    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::InvalidUtf8 { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "invalid byte sequence starts here")].into(),
                ..DiagnosticDetails::default()
            },
            Self::IncompleteUtf8 { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "the codepoint starting here is incomplete")]
                    .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidToken { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "occurs here")].into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidSyntax { span, message }
            | Self::InvalidStructRepr { span, message }
            | Self::InvalidLocalsAttr { span, message } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, message.clone())].into(),
                ..DiagnosticDetails::default()
            },
            Self::UnrecognizedToken { span, token, expected } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, format!("found a {token} here"))].into(),
                help: Some(format!("expected {}", expected.as_slice().join(", or ")).into()),
                ..DiagnosticDetails::default()
            },
            Self::ExtraToken { span, token } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    format!("{token} was found here, but was not expected")
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::UnrecognizedEof { span, expected } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "reached end of file here")].into(),
                help: Some(format!("expected {}", expected.as_slice().join(", or ")).into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidIdentifier { span, .. } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "bare identifiers must be lowercase alphanumeric with '_', quoted identifiers \
                     can include any graphical character"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::UnclosedQuote { start } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *start,
                    "no match for quotation mark starting here"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::CodeBlockTooBig { span }
            | Self::DivisionByZero { span }
            | Self::InvalidLiteral { span, .. }
            | Self::InvalidHexLiteral { span, .. }
            | Self::InvalidBinaryLiteral { span, .. }
            | Self::InvalidMastRoot { span }
            | Self::InvalidLibraryPath { span, .. }
            | Self::ImmediateOutOfRange { span, .. }
            | Self::ModuleTooLarge { span }
            | Self::ModuleTooManyReexports { span }
            | Self::PushOverflow { span, .. }
            | Self::UnqualifiedImport { span }
            | Self::UnnamedReexportOfMastRoot { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                ..DiagnosticDetails::default()
            },
            Self::ControlFlowNestingDepthExceeded { span, max_depth } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "control-flow nesting exceeded the configured depth limit here"
                )]
                .into(),
                help: Some(
                    format!("control-flow nesting exceeded the maximum depth of {max_depth}")
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::ConstantExpressionNestingDepthExceeded { span, max_depth } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "constant expression nesting exceeded the configured depth limit here"
                )]
                .into(),
                help: Some(
                    format!(
                        "constant expression nesting exceeded the maximum depth of {max_depth}"
                    )
                    .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::TypeExpressionNestingDepthExceeded { span, max_depth } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "type expression nesting exceeded the configured depth limit here"
                )]
                .into(),
                help: Some(
                    format!("type expression nesting exceeded the maximum depth of {max_depth}")
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::DocsTooLarge { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("make sure it is less than u16::MAX bytes in length".into()),
                ..DiagnosticDetails::default()
            },
            Self::AttributeConflict { span, prev } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(
                        *span,
                        "conflict occurs because an attribute with the same name has already been \
                         defined"
                    ),
                    Label::new(*prev, "previously defined here")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::AttributeKeyValueConflict { span, prev } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(
                        *span,
                        "conflict occurs because a key with the same name has already been set in \
                         a previous declaration"
                    ),
                    Label::new(*prev, "previously defined here")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidAdvMapKey { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "an Advice Map key must be a word, either in 64-character hex format or in \
                     array-like format `[f0,f1,f2,f3]`"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidSliceConstant { span } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    "slices are only supported over word-sized constants"
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidRange { span, range } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    format!("range used for the word constant slice is malformed: `{range:?}`")
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::EmptySlice { span, range } => DiagnosticDetails {
                labels: alloc::vec![Label::new(
                    *span,
                    format!("range used for the word constant slice is empty: `{range:?}`")
                )]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::UnrecognizedCallConv { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "expected one of: 'fast', 'C', 'wasm', 'canon-lift', or 'canon-lower'".into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidStructAnnotation { span } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some(
                    "expected one of: '@packed', '@packed(N)', '@transparent', or '@align(N)'"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::DeprecatedInstruction { span, replacement, .. } => DiagnosticDetails {
                labels: alloc::vec![Label::new(*span, "this instruction is no longer supported")]
                    .into(),
                help: Some(format!("use `{replacement}` instead").into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidPadValue { span, .. } => DiagnosticDetails {
                labels: alloc::vec![Label::underline(*span)].into(),
                help: Some("valid padding values are 0, 4, and 8".into()),
                ..DiagnosticDetails::default()
            },
            Self::UndefinedSubmodule { span, source_file, .. }
            | Self::AmbiguousSubmoduleLocation { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::underline(*span)].into(),
                ..DiagnosticDetails::default()
            },
            Self::SelfReferentialSubmodule { parent_module_uri, span, source_file, .. } => {
                DiagnosticDetails {
                    source: source_file.as_deref(),
                    labels: alloc::vec![Label::new(
                        *span,
                        "module source resolution rules require this declaration to resolve to \
                         the current source file"
                    )]
                    .into(),
                    help: Some(format!("occurred while parsing {parent_module_uri}").into()),
                    ..DiagnosticDetails::default()
                }
            },
            Self::DuplicateSubmoduleSource { span, source_file, .. } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this declaration resolves to an already visited module source"
                )]
                .into(),
                help: Some(
                    "each module source file can only be owned by one module in a module tree"
                        .into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::CallConvAttributeConflict { cc_span, attr_span } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(
                        *cc_span,
                        "conflict occurs because @callconv conflicts with convention implied by \
                         other attribute"
                    ),
                    Label::new(*attr_span, "this attribute implies @callconv(\"component-model\")")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::ConflictingProtocolAbiAttribute { span, prev } => DiagnosticDetails {
                labels: alloc::vec![
                    Label::new(
                        *span,
                        "this attribute specifies the protocol ABI of this procedure, but a \
                         different ABI was previously specified"
                    ),
                    Label::new(
                        *prev,
                        "this attribute already specifies the protocol ABI for this procedure"
                    )
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::Failed => DiagnosticDetails::default(),
        }
    }
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
            (Self::InvalidSyntax { message: l, .. }, Self::InvalidSyntax { message: r, .. }) => {
                l == r
            },
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
