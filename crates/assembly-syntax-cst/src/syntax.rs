use rowan::Language;

/// The full set of rowan node and token kinds used by the MASM CST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SyntaxKind {
    Tombstone = 0,
    Error,
    SourceFile,
    ModuleDoc,
    Doc,
    Import,
    Constant,
    TypeDecl,
    AdviceMap,
    BeginBlock,
    Procedure,
    Attribute,
    Visibility,
    Signature,
    Block,
    IfOp,
    WhileOp,
    RepeatOp,
    Instruction,
    Path,
    Expr,
    TypeBody,
    Whitespace,
    Newline,
    Comment,
    DocComment,
    Ident,
    SpecialIdent,
    Number,
    QuotedIdent,
    QuotedString,
    At,
    Bang,
    Colon,
    ColonColon,
    Comma,
    Dot,
    DotDot,
    Equal,
    LAngle,
    LBrace,
    LBracket,
    LParen,
    Minus,
    Plus,
    RAngle,
    RArrow,
    RBrace,
    RBracket,
    RParen,
    Semicolon,
    Slash,
    SlashSlash,
    Star,
}

impl SyntaxKind {
    /// Returns `true` if this kind represents trivia that the formatter may preserve but most
    /// typed accessors ignore.
    pub fn is_trivia(self) -> bool {
        matches!(self, Self::Whitespace | Self::Newline | Self::Comment | Self::DocComment)
    }
}

impl From<SyntaxKind> for rowan::SyntaxKind {
    fn from(kind: SyntaxKind) -> Self {
        Self(kind as u16)
    }
}

const ALL_KINDS: [SyntaxKind; SyntaxKind::Star as usize + 1] = [
    SyntaxKind::Tombstone,
    SyntaxKind::Error,
    SyntaxKind::SourceFile,
    SyntaxKind::ModuleDoc,
    SyntaxKind::Doc,
    SyntaxKind::Import,
    SyntaxKind::Constant,
    SyntaxKind::TypeDecl,
    SyntaxKind::AdviceMap,
    SyntaxKind::BeginBlock,
    SyntaxKind::Procedure,
    SyntaxKind::Attribute,
    SyntaxKind::Visibility,
    SyntaxKind::Signature,
    SyntaxKind::Block,
    SyntaxKind::IfOp,
    SyntaxKind::WhileOp,
    SyntaxKind::RepeatOp,
    SyntaxKind::Instruction,
    SyntaxKind::Path,
    SyntaxKind::Expr,
    SyntaxKind::TypeBody,
    SyntaxKind::Whitespace,
    SyntaxKind::Newline,
    SyntaxKind::Comment,
    SyntaxKind::DocComment,
    SyntaxKind::Ident,
    SyntaxKind::SpecialIdent,
    SyntaxKind::Number,
    SyntaxKind::QuotedIdent,
    SyntaxKind::QuotedString,
    SyntaxKind::At,
    SyntaxKind::Bang,
    SyntaxKind::Colon,
    SyntaxKind::ColonColon,
    SyntaxKind::Comma,
    SyntaxKind::Dot,
    SyntaxKind::DotDot,
    SyntaxKind::Equal,
    SyntaxKind::LAngle,
    SyntaxKind::LBrace,
    SyntaxKind::LBracket,
    SyntaxKind::LParen,
    SyntaxKind::Minus,
    SyntaxKind::Plus,
    SyntaxKind::RAngle,
    SyntaxKind::RArrow,
    SyntaxKind::RBrace,
    SyntaxKind::RBracket,
    SyntaxKind::RParen,
    SyntaxKind::Semicolon,
    SyntaxKind::Slash,
    SyntaxKind::SlashSlash,
    SyntaxKind::Star,
];

/// The rowan language marker for MASM CST nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MasmLanguage {}

impl Language for MasmLanguage {
    type Kind = SyntaxKind;

    fn kind_from_raw(raw: rowan::SyntaxKind) -> Self::Kind {
        ALL_KINDS
            .get(raw.0 as usize)
            .copied()
            .unwrap_or_else(|| panic!("invalid syntax kind: {}", raw.0))
    }

    fn kind_to_raw(kind: Self::Kind) -> rowan::SyntaxKind {
        kind.into()
    }
}

/// A rowan syntax node in the MASM CST.
pub type SyntaxNode = rowan::SyntaxNode<MasmLanguage>;
/// A rowan syntax token in the MASM CST.
pub type SyntaxToken = rowan::SyntaxToken<MasmLanguage>;
/// A rowan syntax element in the MASM CST.
pub type SyntaxElement = rowan::SyntaxElement<MasmLanguage>;
