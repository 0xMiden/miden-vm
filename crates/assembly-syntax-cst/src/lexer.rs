use miden_debug_types::{SourceFile, SourceId, SourceSpan};

use crate::syntax::SyntaxKind;

/// A single lossless token produced by the MASM lexer.
///
/// Tokens retain their original text and source span so callers can reconstruct exact source
/// layout, including trivia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'input> {
    kind: SyntaxKind,
    span: SourceSpan,
    text: &'input str,
}

impl<'input> Token<'input> {
    /// Constructs a token from already-classified source text.
    pub fn new(kind: SyntaxKind, span: SourceSpan, text: &'input str) -> Self {
        Self { kind, span, text }
    }

    /// Returns the token kind assigned by the lexer.
    pub fn kind(&self) -> SyntaxKind {
        self.kind
    }

    /// Returns the source span covered by this token.
    pub fn span(&self) -> SourceSpan {
        self.span
    }

    /// Returns the exact source text covered by this token.
    pub fn text(&self) -> &'input str {
        self.text
    }
}

/// Tokenizes a source-managed MASM file into a lossless token stream.
pub fn tokenize(source: &SourceFile) -> Vec<Token<'_>> {
    Lexer::new(source).collect()
}

/// Tokenizes a raw string using [`SourceId::UNKNOWN`] spans.
///
/// This is primarily useful in tests and standalone helpers. Production callers should prefer
/// [`tokenize`] so spans remain attached to a real [`SourceFile`].
pub fn tokenize_text(input: &str) -> Vec<Token<'_>> {
    Lexer::from_raw_parts(SourceId::UNKNOWN, input).collect()
}

/// An iterator over lossless MASM tokens.
///
/// The lexer preserves comments, whitespace, and newlines as ordinary tokens rather than skipping
/// them, which allows the CST and formatter to reason about original layout.
pub struct Lexer<'input> {
    input: &'input str,
    source_id: SourceId,
    offset: usize,
}

impl<'input> Lexer<'input> {
    /// Creates a lexer over a source-managed MASM file.
    pub fn new(source: &'input SourceFile) -> Self {
        Self::from_raw_parts(source.id(), source.as_str())
    }

    /// Creates a lexer from raw text and an explicit source id.
    ///
    /// This is the lowest-level constructor used by [`tokenize_text`] and parser test helpers.
    pub fn from_raw_parts(source_id: SourceId, input: &'input str) -> Self {
        Self { input, source_id, offset: 0 }
    }

    fn is_eof(&self) -> bool {
        self.offset >= self.input.len()
    }

    fn current_char(&self) -> Option<char> {
        self.input[self.offset..].chars().next()
    }

    fn advance_char(&mut self) -> Option<char> {
        let ch = self.current_char()?;
        self.offset += ch.len_utf8();
        Some(ch)
    }

    fn advance_while(&mut self, predicate: impl Fn(char) -> bool) {
        while let Some(ch) = self.current_char() {
            if !predicate(ch) {
                break;
            }
            self.advance_char();
        }
    }

    fn token(&self, kind: SyntaxKind, start: usize, end: usize) -> Token<'input> {
        let span = SourceSpan::try_from_range(self.source_id, start..end)
            .expect("source files larger than 4GiB are not supported");
        Token::new(kind, span, &self.input[start..end])
    }

    fn lex_trivia(&mut self, start: usize, first: char) -> Token<'input> {
        match first {
            ' ' | '\t' => {
                self.advance_while(|ch| matches!(ch, ' ' | '\t'));
                self.token(SyntaxKind::Whitespace, start, self.offset)
            },
            '\n' => {
                self.advance_char();
                self.token(SyntaxKind::Newline, start, self.offset)
            },
            '\r' => {
                self.advance_char();
                if self.current_char() == Some('\n') {
                    self.advance_char();
                }
                self.token(SyntaxKind::Newline, start, self.offset)
            },
            '#' => {
                self.advance_char();
                let kind = if self.current_char() == Some('!') {
                    self.advance_char();
                    SyntaxKind::DocComment
                } else {
                    SyntaxKind::Comment
                };
                self.advance_while(|ch| ch != '\n' && ch != '\r');
                self.token(kind, start, self.offset)
            },
            _ => unreachable!("unexpected trivia character: {first:?}"),
        }
    }

    fn lex_identifier(&mut self, start: usize, first: char) -> Token<'input> {
        if first == '$' {
            self.advance_char();
            self.advance_while(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
            return self.token(SyntaxKind::SpecialIdent, start, self.offset);
        }

        self.advance_char();
        self.advance_while(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        self.token(SyntaxKind::Ident, start, self.offset)
    }

    fn lex_number(&mut self, start: usize) -> Token<'input> {
        self.advance_char();

        if self.input[start..].starts_with("0x") || self.input[start..].starts_with("0X") {
            self.advance_char();
            self.advance_while(|ch| ch.is_ascii_hexdigit());
        } else if self.input[start..].starts_with("0b") || self.input[start..].starts_with("0B") {
            self.advance_char();
            self.advance_while(|ch| matches!(ch, '0' | '1'));
        } else {
            self.advance_while(|ch| ch.is_ascii_digit());
        }

        self.token(SyntaxKind::Number, start, self.offset)
    }

    fn lex_quoted(&mut self, start: usize) -> Token<'input> {
        self.advance_char();

        let mut escaped = false;
        let mut closed = false;
        let mut identifier_like = true;
        while let Some(ch) = self.current_char() {
            match ch {
                '\n' | '\r' => break,
                '\\' => {
                    escaped = true;
                    identifier_like = false;
                    self.advance_char();
                    if self.current_char().is_some() {
                        self.advance_char();
                    }
                },
                '"' => {
                    self.advance_char();
                    closed = true;
                    break;
                },
                _ => {
                    identifier_like &= ch.is_ascii_alphanumeric() || ch.is_ascii_graphic();
                    self.advance_char();
                },
            }
        }

        if !closed {
            return self.token(SyntaxKind::Error, start, self.offset);
        }

        let kind = if escaped || !identifier_like {
            SyntaxKind::QuotedString
        } else {
            SyntaxKind::QuotedIdent
        };
        self.token(kind, start, self.offset)
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = Token<'input>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_eof() {
            return None;
        }

        let start = self.offset;
        let current = self.current_char()?;
        let token = match current {
            ' ' | '\t' | '\n' | '\r' | '#' => self.lex_trivia(start, current),
            'a'..='z' | 'A'..='Z' | '_' | '$' => self.lex_identifier(start, current),
            '0'..='9' => self.lex_number(start),
            '"' => self.lex_quoted(start),
            '@' => {
                self.advance_char();
                self.token(SyntaxKind::At, start, self.offset)
            },
            '!' => {
                self.advance_char();
                self.token(SyntaxKind::Bang, start, self.offset)
            },
            ':' => {
                self.advance_char();
                let kind = if self.current_char() == Some(':') {
                    self.advance_char();
                    SyntaxKind::ColonColon
                } else {
                    SyntaxKind::Colon
                };
                self.token(kind, start, self.offset)
            },
            ',' => {
                self.advance_char();
                self.token(SyntaxKind::Comma, start, self.offset)
            },
            '.' => {
                self.advance_char();
                let kind = if self.current_char() == Some('.') {
                    self.advance_char();
                    SyntaxKind::DotDot
                } else {
                    SyntaxKind::Dot
                };
                self.token(kind, start, self.offset)
            },
            '=' => {
                self.advance_char();
                self.token(SyntaxKind::Equal, start, self.offset)
            },
            '<' => {
                self.advance_char();
                self.token(SyntaxKind::LAngle, start, self.offset)
            },
            '>' => {
                self.advance_char();
                self.token(SyntaxKind::RAngle, start, self.offset)
            },
            '{' => {
                self.advance_char();
                self.token(SyntaxKind::LBrace, start, self.offset)
            },
            '}' => {
                self.advance_char();
                self.token(SyntaxKind::RBrace, start, self.offset)
            },
            '[' => {
                self.advance_char();
                self.token(SyntaxKind::LBracket, start, self.offset)
            },
            ']' => {
                self.advance_char();
                self.token(SyntaxKind::RBracket, start, self.offset)
            },
            '(' => {
                self.advance_char();
                self.token(SyntaxKind::LParen, start, self.offset)
            },
            ')' => {
                self.advance_char();
                self.token(SyntaxKind::RParen, start, self.offset)
            },
            '-' => {
                self.advance_char();
                let kind = if self.current_char() == Some('>') {
                    self.advance_char();
                    SyntaxKind::RArrow
                } else {
                    SyntaxKind::Minus
                };
                self.token(kind, start, self.offset)
            },
            '+' => {
                self.advance_char();
                self.token(SyntaxKind::Plus, start, self.offset)
            },
            '/' => {
                self.advance_char();
                let kind = if self.current_char() == Some('/') {
                    self.advance_char();
                    SyntaxKind::SlashSlash
                } else {
                    SyntaxKind::Slash
                };
                self.token(kind, start, self.offset)
            },
            '*' => {
                self.advance_char();
                self.token(SyntaxKind::Star, start, self.offset)
            },
            ';' => {
                self.advance_char();
                self.token(SyntaxKind::Semicolon, start, self.offset)
            },
            _ => {
                self.advance_char();
                self.token(SyntaxKind::Error, start, self.offset)
            },
        };

        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_debug_types::{SourceFile, SourceId, SourceLanguage, SourceSpan, Uri};
    use pretty_assertions::assert_eq;

    use super::{tokenize, tokenize_text};
    use crate::syntax::SyntaxKind;

    #[test]
    fn preserves_trivia_and_simple_tokens() {
        let source = "proc foo\r\n    # comment\r\n    push.1.2 add\r\nend\r\n";
        let tokens = tokenize_text(source);
        let actual = tokens
            .iter()
            .map(|token| (token.kind(), token.text().to_string()))
            .collect::<Vec<_>>();
        let expected = vec![
            (SyntaxKind::Ident, "proc".to_string()),
            (SyntaxKind::Whitespace, " ".to_string()),
            (SyntaxKind::Ident, "foo".to_string()),
            (SyntaxKind::Newline, "\r\n".to_string()),
            (SyntaxKind::Whitespace, "    ".to_string()),
            (SyntaxKind::Comment, "# comment".to_string()),
            (SyntaxKind::Newline, "\r\n".to_string()),
            (SyntaxKind::Whitespace, "    ".to_string()),
            (SyntaxKind::Ident, "push".to_string()),
            (SyntaxKind::Dot, ".".to_string()),
            (SyntaxKind::Number, "1".to_string()),
            (SyntaxKind::Dot, ".".to_string()),
            (SyntaxKind::Number, "2".to_string()),
            (SyntaxKind::Whitespace, " ".to_string()),
            (SyntaxKind::Ident, "add".to_string()),
            (SyntaxKind::Newline, "\r\n".to_string()),
            (SyntaxKind::Ident, "end".to_string()),
            (SyntaxKind::Newline, "\r\n".to_string()),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn classifies_doc_comments_and_special_identifiers() {
        let source = "#! docs\nadv.push_mapval $kernel\n";
        let tokens = tokenize_text(source);
        let actual = tokens
            .iter()
            .map(|token| (token.kind(), token.text().to_string()))
            .collect::<Vec<_>>();
        let expected = vec![
            (SyntaxKind::DocComment, "#! docs".to_string()),
            (SyntaxKind::Newline, "\n".to_string()),
            (SyntaxKind::Ident, "adv".to_string()),
            (SyntaxKind::Dot, ".".to_string()),
            (SyntaxKind::Ident, "push_mapval".to_string()),
            (SyntaxKind::Whitespace, " ".to_string()),
            (SyntaxKind::SpecialIdent, "$kernel".to_string()),
            (SyntaxKind::Newline, "\n".to_string()),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn tracks_source_spans_when_tokenizing_source_files() {
        let source = Arc::new(SourceFile::new(
            SourceId::new(7),
            SourceLanguage::Masm,
            Uri::new("memory:///lexer-span-test.masm"),
            "proc foo\n".to_string().into_boxed_str(),
        ));

        let tokens = tokenize(source.as_ref());
        assert_eq!(tokens[0].text(), "proc");
        assert_eq!(tokens[0].span(), SourceSpan::new(source.id(), 0u32..4u32));
        assert_eq!(tokens[2].text(), "foo");
        assert_eq!(tokens[2].span(), SourceSpan::new(source.id(), 5u32..8u32));
    }
}
