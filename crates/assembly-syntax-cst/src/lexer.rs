use core::ops::Range;

use crate::syntax::SyntaxKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'input> {
    kind: SyntaxKind,
    span: Range<usize>,
    text: &'input str,
}

impl<'input> Token<'input> {
    pub fn new(kind: SyntaxKind, span: Range<usize>, text: &'input str) -> Self {
        Self { kind, span, text }
    }

    pub fn kind(&self) -> SyntaxKind {
        self.kind
    }

    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    pub fn text(&self) -> &'input str {
        self.text
    }
}

pub fn tokenize(input: &str) -> Vec<Token<'_>> {
    Lexer::new(input).collect()
}

pub struct Lexer<'input> {
    input: &'input str,
    offset: usize,
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input str) -> Self {
        Self { input, offset: 0 }
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
        Token::new(kind, start..end, &self.input[start..end])
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
    use pretty_assertions::assert_eq;

    use super::tokenize;
    use crate::syntax::SyntaxKind;

    #[test]
    fn preserves_trivia_and_simple_tokens() {
        let source = "proc foo\r\n    # comment\r\n    push.1.2 add\r\nend\r\n";
        let tokens = tokenize(source);
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
        let tokens = tokenize(source);
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
}
