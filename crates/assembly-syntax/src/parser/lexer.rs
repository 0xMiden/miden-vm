use alloc::{borrow::Cow, string::String};
use core::{num::IntErrorKind, ops::Range};

use miden_core::field::PrimeCharacteristicRing;
use miden_debug_types::{ByteOffset, SourceId, SourceSpan};

use super::{
    BinEncodedValue, BinErrorKind, DocumentationType, HexErrorKind, IntValue, LiteralErrorKind,
    ParsingError, Scanner, Token, WordValue,
};
use crate::Felt;

/// The value produced by the [Lexer] when iterated
///
/// A successfully lexed token is wrapped in a tuple with the start and end byte offsets, where
/// the end offset is exclusive. We explicitly use a tuple here, and not something like Span<T>,
/// because this "triple" is the structure expected by the LALRPOP parser generator when used with
/// a custom lexer like ours.
pub type Lexed<'input> = Result<(u32, Token<'input>, u32), ParsingError>;

/// Pops a single token from the [Lexer]
macro_rules! pop {
    ($lex:ident) => {{
        $lex.skip();
    }};
    ($lex:ident, $token:expr) => {{
        $lex.skip();
        Ok($token)
    }};
}

/// Pops two tokens from the [Lexer]
macro_rules! pop2 {
    ($lex:ident) => {{
        $lex.skip();
        $lex.skip();
    }};
    ($lex:ident, $token:expr) => {{
        $lex.skip();
        $lex.skip();
        Ok($token)
    }};
}

// LEXER
// ================================================================================================

/// The lexer that is used to perform lexical analysis Miden Assembly grammar. The lexer implements
/// the `Iterator` trait, so in order to retrieve the tokens, you simply have to iterate over it.
///
/// # Errors
///
/// Because the lexer is implemented as an iterator over tokens, this means that you can continue
/// to get tokens even if a lexical error occurs. The lexer will attempt to recover from an error
/// by injecting tokens it expects.
///
/// If an error is unrecoverable, the lexer will continue to produce tokens, but there is no
/// guarantee that parsing them will produce meaningful results, it is primarily to assist in
/// gathering as many errors as possible.
pub struct Lexer<'input> {
    /// The [SourceId] of the file being lexed, for use in producing spans in lexer diagnostics
    source_id: SourceId,

    /// The scanner produces a sequence of chars + location, and can be controlled
    /// The location type is usize
    scanner: Scanner<'input>,

    /// The most recent token to be lexed.
    /// At the start and end, this should be Token::Eof
    token: Token<'input>,

    /// The position in the input where the current token starts
    /// At the start this will be the byte index of the beginning of the input
    token_start: usize,

    /// The position in the input where the current token ends
    /// At the start this will be the byte index of the beginning of the input
    token_end: usize,

    /// The current line number
    line_num: usize,

    /// When we have reached true Eof, this gets set to true, and the only token
    /// produced after that point is Token::Eof, or None, depending on how you are
    /// consuming the lexer
    eof: bool,
    empty: bool,

    // A DFA for keyword matching
    keywords: aho_corasick::AhoCorasick,

    /// If an error occurs during tokenization, it is held here
    error: Option<ParsingError>,
}

impl<'input> Lexer<'input> {
    /// Produces an instance of the lexer with the lexical analysis to be performed on the `input`
    /// string. Note that no lexical analysis occurs until the lexer has been iterated over.
    pub fn new(source_id: SourceId, scanner: Scanner<'input>) -> Self {
        let start = scanner.start();
        let keywords = Token::keyword_searcher();
        let mut lexer = Self {
            source_id,
            scanner,
            token: Token::Eof,
            token_start: start,
            token_end: start,
            line_num: 0,
            eof: false,
            empty: false,
            keywords,
            error: None,
        };
        lexer.advance();
        lexer
    }

    pub fn lex(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(err) = self.error.take() {
            return Some(Err(err));
        }

        if self.eof && matches!(self.token, Token::Eof) {
            // Emit a single Eof token at the end, then None after
            if self.empty {
                return None;
            } else {
                self.empty = true;
                let end = self.token_end as u32;
                return Some(Ok((end, Token::Eof, end)));
            }
        }

        let token = core::mem::replace(&mut self.token, Token::Eof);
        let start = self.token_start;
        let end = self.token_end;
        self.advance();
        Some(Ok((start as u32, token, end as u32)))
    }

    fn advance(&mut self) {
        self.advance_start();
        match self.tokenize() {
            Ok(tok) => {
                self.token = tok;
            },
            Err(err) => {
                self.error = Some(err);
            },
        }
    }

    #[inline]
    fn advance_start(&mut self) {
        let mut position: usize;
        loop {
            let (pos, c) = self.scanner.read();

            position = pos;

            if c == '\0' {
                self.eof = true;
                return;
            }

            if c.is_whitespace() {
                if c == '\n' {
                    self.line_num += 1;
                }
                self.scanner.advance();
                continue;
            }

            break;
        }

        self.token_start = position;
    }

    #[inline]
    fn pop(&mut self) -> char {
        let (pos, c) = self.scanner.pop();
        self.token_end = pos + c.len_utf8();
        c
    }

    #[inline]
    fn peek(&mut self) -> char {
        let (_, c) = self.scanner.peek();
        c
    }

    #[inline]
    #[expect(unused)]
    fn peek_next(&mut self) -> char {
        let (_, c) = self.scanner.peek_next();
        c
    }

    #[inline]
    fn read(&mut self) -> char {
        let (_, c) = self.scanner.read();
        c
    }

    #[inline]
    fn skip(&mut self) {
        self.pop();
    }

    /// Get the span for the current token in `Source`.
    #[inline]
    fn span(&self) -> SourceSpan {
        assert!(self.token_start <= self.token_end, "invalid range");
        assert!(self.token_end <= u32::MAX as usize, "file too large");
        SourceSpan::new(self.source_id, (self.token_start as u32)..(self.token_end as u32))
    }

    #[inline]
    fn slice_span(&self, span: impl Into<Range<u32>>) -> &'input str {
        let range = span.into();
        self.scanner.slice((range.start as usize)..(range.end as usize))
    }

    /// Get a string slice of the current token.
    #[inline]
    fn slice(&self) -> &'input str {
        self.slice_span(self.span())
    }

    #[inline]
    fn skip_whitespace(&mut self) {
        let mut c: char;
        loop {
            c = self.read();

            if !c.is_whitespace() {
                break;
            }

            if c == '\n' {
                self.line_num += 1;
            }

            self.skip();
        }
    }

    fn tokenize(&mut self) -> Result<Token<'input>, ParsingError> {
        let c = self.read();

        if c == '#' {
            match self.peek() {
                '!' => {
                    self.skip();
                    self.skip();
                    return self.lex_docs();
                },
                _ => {
                    self.skip();
                    self.skip_comment();
                    return Ok(Token::Comment);
                },
            }
        }

        if c == '\0' {
            self.eof = true;
            return Ok(Token::Eof);
        }

        if c.is_whitespace() {
            self.skip_whitespace();
        }

        match self.read() {
            '@' => pop!(self, Token::At),
            '!' => pop!(self, Token::Bang),
            ':' => match self.peek() {
                ':' => pop2!(self, Token::ColonColon),
                _ => pop!(self, Token::Colon),
            },
            ';' => pop!(self, Token::Semicolon),
            '.' => match self.peek() {
                '.' => pop2!(self, Token::Range),
                _ => pop!(self, Token::Dot),
            },
            ',' => pop!(self, Token::Comma),
            '=' => pop!(self, Token::Equal),
            '<' => pop!(self, Token::Langle),
            '{' => pop!(self, Token::Lbrace),
            '[' => pop!(self, Token::Lbracket),
            '(' => pop!(self, Token::Lparen),
            '>' => pop!(self, Token::Rangle),
            '}' => pop!(self, Token::Rbrace),
            ']' => pop!(self, Token::Rbracket),
            ')' => pop!(self, Token::Rparen),
            '-' => match self.peek() {
                '>' => pop2!(self, Token::Rstab),
                _ => pop!(self, Token::Minus),
            },
            '+' => pop!(self, Token::Plus),
            '/' => match self.peek() {
                '/' => pop2!(self, Token::SlashSlash),
                _ => pop!(self, Token::Slash),
            },
            '*' => pop!(self, Token::Star),
            '$' => self.lex_special_identifier(),
            '"' => self.lex_quoted_identifier_or_string(),
            '0' => match self.peek() {
                'x' => {
                    self.skip();
                    self.skip();
                    self.lex_hex()
                },
                'b' => {
                    self.skip();
                    self.skip();
                    self.lex_bin()
                },
                '0'..='9' => self.lex_number(),
                _ => pop!(self, Token::Int(0)),
            },
            '1'..='9' => self.lex_number(),
            'a'..='z' => self.lex_keyword_or_ident(),
            'A'..='Z' => self.lex_identifier(),
            '_' => match self.peek() {
                c if c.is_ascii_alphanumeric() => self.lex_identifier(),
                _ => Err(ParsingError::InvalidToken { span: self.span() }),
            },
            _ => Err(ParsingError::InvalidToken { span: self.span() }),
        }
    }

    fn lex_docs(&mut self) -> Result<Token<'input>, ParsingError> {
        let mut buf = String::new();

        let mut c;
        let mut line_start = self.token_start + 2;
        let is_module_doc = self.line_num == 0;
        loop {
            c = self.read();

            if c == '\0' {
                self.eof = true;
                buf.push_str(self.slice_span((line_start as u32)..(self.token_end as u32)).trim());

                let is_first_line = self.line_num == 0;
                break Ok(Token::DocComment(if is_first_line {
                    DocumentationType::Module(buf)
                } else {
                    DocumentationType::Form(buf)
                }));
            }

            if c == '\n' {
                self.line_num += 1;

                buf.push_str(self.slice_span((line_start as u32)..(self.token_end as u32)).trim());
                buf.push('\n');

                self.skip();
                c = self.read();
                match c {
                    '#' if self.peek() == '!' => {
                        self.skip();
                        self.skip();
                        line_start = self.token_end;
                        continue;
                    },
                    _ if is_module_doc => {
                        break Ok(Token::DocComment(DocumentationType::Module(buf)));
                    },
                    _ => {
                        break Ok(Token::DocComment(DocumentationType::Form(buf)));
                    },
                }
            }

            self.skip();
        }
    }

    fn skip_comment(&mut self) {
        let mut c;
        loop {
            c = self.read();

            if c == '\n' {
                self.skip();
                self.line_num += 1;
                break;
            }

            if c == '\0' {
                self.eof = true;
                break;
            }

            self.skip();
        }
    }

    fn lex_keyword_or_ident(&mut self) -> Result<Token<'input>, ParsingError> {
        let c = self.pop();
        debug_assert!(c.is_ascii_alphabetic() && c.is_lowercase());

        loop {
            match self.read() {
                '_' | '0'..='9' => self.skip(),
                c if c.is_ascii_alphabetic() => self.skip(),
                _ => break,
            }
        }

        let name = self.slice();
        match name {
            "exp" => {
                // Special handling for the `exp.uXX` tokenization
                if self.read() == '.' && self.peek() == 'u' {
                    pop2!(self, Token::ExpU)
                } else {
                    Ok(Token::Exp)
                }
            },
            _ => Ok(Token::from_keyword_or_ident_with_searcher(name, &self.keywords)),
        }
    }

    fn lex_quoted_identifier_or_string(&mut self) -> Result<Token<'input>, ParsingError> {
        // Skip quotation mark
        self.skip();

        let mut is_identifier = true;
        let quote_size = ByteOffset::from_char_len('"');
        loop {
            match self.read() {
                '\0' | '\n' => {
                    break Err(ParsingError::UnclosedQuote {
                        start: SourceSpan::at(self.source_id, self.span().start()),
                    });
                },
                '\\' => {
                    is_identifier = false;
                    self.skip();
                    match self.read() {
                        '"' | '\n' => {
                            self.skip();
                        },
                        _ => (),
                    }
                },
                '"' => {
                    let span = self.span();
                    let start = span.start() + quote_size;
                    let span = SourceSpan::new(self.source_id, start..span.end());

                    self.skip();
                    break Ok(if is_identifier {
                        Token::QuotedIdent(self.slice_span(span))
                    } else {
                        Token::QuotedString(self.slice_span(span))
                    });
                },
                c if c.is_alphanumeric() || c.is_ascii_graphic() => {
                    self.skip();
                },
                _ => {
                    is_identifier = false;
                    self.skip();
                },
            }
        }
    }

    fn lex_identifier(&mut self) -> Result<Token<'input>, ParsingError> {
        let c = self.pop();
        debug_assert!(c.is_ascii_alphabetic() || c == '_');

        let mut is_constant_ident = c.is_ascii_uppercase() || c == '_';

        loop {
            match self.read() {
                '_' | '0'..='9' => self.skip(),
                c if c.is_ascii_alphabetic() => {
                    is_constant_ident &= c.is_ascii_uppercase();
                    self.skip();
                },
                _ => break,
            }
        }

        if is_constant_ident {
            Ok(Token::ConstantIdent(self.slice()))
        } else {
            Ok(Token::Ident(self.slice()))
        }
    }

    fn lex_special_identifier(&mut self) -> Result<Token<'input>, ParsingError> {
        let c = self.pop();
        debug_assert_eq!(c, '$');

        loop {
            match self.read() {
                '_' | '0'..='9' => self.skip(),
                c if c.is_ascii_lowercase() => self.skip(),
                _ => break,
            }
        }

        match self.slice() {
            id @ ("$kernel" | "$exec") => Ok(Token::Ident(id)),
            _ => {
                let start = self.span().start();
                let span = SourceSpan::at(self.span().source_id(), start);
                Err(ParsingError::InvalidToken { span })
            },
        }
    }

    fn lex_number(&mut self) -> Result<Token<'input>, ParsingError> {
        // Expect the first character to be a digit
        let c = self.read();
        debug_assert!(c.is_ascii_digit());

        while let '0'..='9' = self.read() {
            self.skip();
        }

        self.slice()
            .parse::<u64>()
            .map_err(|error| ParsingError::InvalidLiteral {
                span: self.span(),
                kind: int_error_kind_to_literal_error_kind(
                    error.kind(),
                    LiteralErrorKind::FeltOverflow,
                ),
            })
            .map(Token::Int)
    }

    fn lex_hex(&mut self) -> Result<Token<'input>, ParsingError> {
        // Expect the first character to be a valid hexadecimal digit
        debug_assert!(self.read().is_ascii_hexdigit());

        loop {
            // If we hit a non-hex digit, we're done
            let c1 = self.read();
            if !c1.is_ascii_hexdigit() {
                break;
            }
            self.skip();

            // All hex-encoded bytes are zero-padded, and thus occur
            // in pairs, if we observe a non-hex digit at this point,
            // it is invalid
            let c2 = self.read();
            if !c2.is_ascii_hexdigit() {
                // For odd-length hex strings, we need to handle this by
                // adjusting the span to not include the unpaired character
                // and let parse_hex handle the padding
                break;
            }
            self.skip();
        }

        let span = self.span();
        let start = span.start();
        let end = span.end();
        let digit_start = start.to_u32() + 2;
        let span = SourceSpan::new(span.source_id(), start..end);
        parse_hex(span, self.slice_span(digit_start..end.to_u32()))
    }

    fn lex_bin(&mut self) -> Result<Token<'input>, ParsingError> {
        // Expect the first character to be a valid binary digit
        debug_assert!(is_ascii_binary(self.read()));

        loop {
            // If we hit a non-binary digit, we're done
            let c1 = self.read();
            if !is_ascii_binary(c1) {
                break;
            }
            self.skip();
        }

        let span = self.span();
        let start = span.start();
        let digit_start = start.to_u32() + 2;
        let end = span.end();
        let span = SourceSpan::new(span.source_id(), start..end);
        let value = parse_bin(span, self.slice_span(digit_start..end.to_u32()))?;
        Ok(Token::BinValue(value))
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = Lexed<'input>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut res = self.lex();
        while let Some(Ok((_, Token::Comment, _))) = res {
            res = self.lex();
        }
        res
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn pad_hex_if_needed<'a>(hex: &'a str) -> Cow<'a, str> {
    if hex.len().is_multiple_of(2) {
        Cow::Borrowed(hex)
    } else {
        // allocate once, with exact capacity
        let mut s = alloc::string::String::with_capacity(hex.len() + 1);
        s.push('0');
        s.push_str(hex);
        Cow::Owned(s)
    }
}

fn parse_hex<'input>(
    span: SourceSpan,
    hex_digits: &'input str,
) -> Result<Token<'input>, ParsingError> {
    use miden_core::{Felt, field::PrimeField64};

    // Handle odd-length hex strings by padding with a leading zero
    let hex_digits = pad_hex_if_needed(hex_digits);

    match hex_digits.len() {
        // Felt - allow all even lengths up to 16
        n if n <= 16 && n.is_multiple_of(2) => {
            let value = u64::from_str_radix(&hex_digits, 16).map_err(|error| {
                ParsingError::InvalidLiteral {
                    span,
                    kind: int_error_kind_to_literal_error_kind(
                        error.kind(),
                        LiteralErrorKind::FeltOverflow,
                    ),
                }
            })?;
            if value >= Felt::ORDER_U64 {
                return Err(ParsingError::InvalidLiteral {
                    span,
                    kind: LiteralErrorKind::FeltOverflow,
                });
            }
            Ok(Token::HexValue(shrink_u64_hex(value)))
        },
        // Word
        64 => {
            let mut word = [Felt::ZERO; 4];
            for (index, element) in word.iter_mut().enumerate() {
                let offset = index * 16;
                let mut felt_bytes = [0u8; 8];
                let digits = &hex_digits[offset..(offset + 16)];
                for (byte_idx, byte) in felt_bytes.iter_mut().enumerate() {
                    let byte_str = &digits[(byte_idx * 2)..((byte_idx * 2) + 2)];
                    *byte = u8::from_str_radix(byte_str, 16).map_err(|error| {
                        ParsingError::InvalidLiteral {
                            span,
                            kind: int_error_kind_to_literal_error_kind(
                                error.kind(),
                                LiteralErrorKind::FeltOverflow,
                            ),
                        }
                    })?;
                }
                let value = u64::from_le_bytes(felt_bytes);
                if value >= Felt::ORDER_U64 {
                    return Err(ParsingError::InvalidLiteral {
                        span,
                        kind: LiteralErrorKind::FeltOverflow,
                    });
                }
                *element = Felt::new(value);
            }
            Ok(Token::HexWord(WordValue(word)))
        },
        // Invalid
        n if n > 64 => Err(ParsingError::InvalidHexLiteral { span, kind: HexErrorKind::TooLong }),
        _ => Err(ParsingError::InvalidHexLiteral { span, kind: HexErrorKind::Invalid }),
    }
}

fn parse_bin(span: SourceSpan, bin_digits: &str) -> Result<BinEncodedValue, ParsingError> {
    if bin_digits.len() <= 32 {
        let value =
            u32::from_str_radix(bin_digits, 2).map_err(|error| ParsingError::InvalidLiteral {
                span,
                kind: int_error_kind_to_literal_error_kind(
                    error.kind(),
                    LiteralErrorKind::U32Overflow,
                ),
            })?;
        Ok(shrink_u32_bin(value))
    } else {
        Err(ParsingError::InvalidBinaryLiteral { span, kind: BinErrorKind::TooLong })
    }
}

#[inline(always)]
fn is_ascii_binary(c: char) -> bool {
    matches!(c, '0'..='1')
}

#[inline]
pub fn shrink_u64_hex(n: u64) -> IntValue {
    if n <= (u8::MAX as u64) {
        IntValue::U8(n as u8)
    } else if n <= (u16::MAX as u64) {
        IntValue::U16(n as u16)
    } else if n <= (u32::MAX as u64) {
        IntValue::U32(n as u32)
    } else {
        IntValue::Felt(Felt::new(n))
    }
}

#[inline]
fn shrink_u32_bin(n: u32) -> BinEncodedValue {
    if n <= (u8::MAX as u32) {
        BinEncodedValue::U8(n as u8)
    } else if n <= (u16::MAX as u32) {
        BinEncodedValue::U16(n as u16)
    } else {
        BinEncodedValue::U32(n)
    }
}

#[inline]
fn int_error_kind_to_literal_error_kind(
    kind: &IntErrorKind,
    overflow: LiteralErrorKind,
) -> LiteralErrorKind {
    match kind {
        IntErrorKind::Empty => LiteralErrorKind::Empty,
        IntErrorKind::InvalidDigit => LiteralErrorKind::InvalidDigit,
        IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => overflow,
        _ => unreachable!(),
    }
}
