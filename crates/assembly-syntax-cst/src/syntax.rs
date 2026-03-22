use rowan::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SyntaxKind {
    Tombstone = 0,
    Error,
    SourceFile,
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

pub type SyntaxNode = rowan::SyntaxNode<MasmLanguage>;
pub type SyntaxToken = rowan::SyntaxToken<MasmLanguage>;
pub type SyntaxElement = rowan::SyntaxElement<MasmLanguage>;
