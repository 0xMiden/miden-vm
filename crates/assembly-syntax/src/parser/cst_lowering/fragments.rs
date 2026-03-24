use alloc::{
    borrow::Cow,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax_cst::{
    SyntaxKind, SyntaxToken,
    ast::{AstNode, Expr as CstExpr, TypeBody as CstTypeBody},
};
use miden_core::{Felt, field::PrimeField64};
use miden_debug_types::{SourceSpan, Span, Spanned};

use super::context::LoweringContext;
use crate::{
    Path,
    ast::{
        self,
        types::{AddressSpace, Type, TypeRepr},
    },
    parser::{HexErrorKind, IntValue, LiteralErrorKind, ParsingError, WordValue},
};

pub(super) fn lower_constant_expr(
    context: &mut LoweringContext<'_>,
    expr: &CstExpr,
) -> Result<ast::ConstantExpr, ParsingError> {
    let span = context.parse().span_for_node(expr.syntax());
    let tokens = expr.significant_tokens().collect::<Vec<_>>();
    let mut parser = FragmentParser::new(context, tokens, span);
    let expr = parser.parse_constant_expr()?;
    parser.expect_eof("unexpected trailing tokens in constant expression")?;
    Ok(expr)
}

pub(super) fn lower_type_expr_from_alias_body(
    context: &mut LoweringContext<'_>,
    body: &CstTypeBody,
) -> Result<ast::TypeExpr, ParsingError> {
    let span = context.parse().span_for_node(body.syntax());
    let tokens = significant_tokens(body.syntax());
    let mut parser = FragmentParser::new(context, tokens, span);
    parser.expect_kind(SyntaxKind::Equal, "expected `=` in type declaration")?;
    let ty = parser.parse_type_expr()?;
    parser.expect_eof("unexpected trailing tokens in type declaration")?;
    Ok(ty)
}

fn significant_tokens(node: &miden_assembly_syntax_cst::syntax::SyntaxNode) -> Vec<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

struct FragmentParser<'a, 'b> {
    context: &'a mut LoweringContext<'b>,
    tokens: Vec<SyntaxToken>,
    pos: usize,
    span: SourceSpan,
}

impl<'a, 'b> FragmentParser<'a, 'b> {
    fn new(
        context: &'a mut LoweringContext<'b>,
        tokens: Vec<SyntaxToken>,
        span: SourceSpan,
    ) -> Self {
        Self { context, tokens, pos: 0, span }
    }

    fn parse_constant_expr(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        if self.is_eof() {
            return Err(self.invalid_syntax("expected a constant expression"));
        }
        self.parse_constant_expr_bp(0)
    }

    fn parse_constant_expr_bp(
        &mut self,
        min_precedence: u8,
    ) -> Result<ast::ConstantExpr, ParsingError> {
        let mut lhs = self.parse_constant_term()?;
        while let Some((precedence, op)) = self.current_constant_operator() {
            if precedence < min_precedence {
                break;
            }

            self.bump();
            let rhs = self.parse_constant_expr_bp(precedence + 1)?;
            let span = join_spans(lhs.span(), rhs.span());
            lhs = ast::ConstantExpr::BinaryOp {
                span,
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
            .try_fold()?;
        }

        Ok(lhs)
    }

    fn parse_constant_term(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        if self.at_kind(SyntaxKind::LParen) {
            self.bump();
            let expr = self.parse_constant_expr()?;
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close constant expression")?;
            return Ok(expr);
        }

        if (self.at_keyword("word") || self.at_keyword("event"))
            && self.peek_kind(1) == Some(SyntaxKind::LParen)
        {
            return self.parse_hash_constant();
        }

        if self.at_kind(SyntaxKind::LBracket) {
            return self.parse_word_literal();
        }

        let Some(token) = self.current() else {
            return Err(self.invalid_syntax("expected a constant term"));
        };

        match token.kind() {
            SyntaxKind::Number => match parse_numeric_token(self.token_span(&token), token.text())?
            {
                ParsedNumeric::Int(value) => {
                    self.bump();
                    Ok(ast::ConstantExpr::Int(Span::new(self.token_span(&token), value)))
                },
                ParsedNumeric::Word(value) => {
                    self.bump();
                    Ok(ast::ConstantExpr::Word(Span::new(self.token_span(&token), value)))
                },
            },
            SyntaxKind::QuotedString | SyntaxKind::QuotedIdent => {
                let token = self.bump().expect("quoted string token should exist");
                let value = self.lower_string_token(&token)?;
                Ok(ast::ConstantExpr::String(value))
            },
            _ => {
                let path = self.parse_path(PathMode::Constant)?;
                Ok(ast::ConstantExpr::Var(path))
            },
        }
    }

    fn parse_hash_constant(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        let name = self.bump().expect("hash-like identifier should be present").text().to_string();
        let lparen = self.expect_kind(SyntaxKind::LParen, "expected `(` after hash function")?;
        let value = match self.current() {
            Some(token)
                if matches!(token.kind(), SyntaxKind::QuotedString | SyntaxKind::QuotedIdent) =>
            {
                let token = self.bump().expect("quoted string token should be present");
                self.lower_string_token(&token)?
            },
            _ => return Err(self.invalid_syntax("expected a quoted string argument")),
        };
        let rparen = self.expect_kind(SyntaxKind::RParen, "expected `)` to close hash function")?;
        let span = join_spans(self.token_span(&lparen), self.token_span(&rparen));
        match name.as_str() {
            "word" => Ok(ast::ConstantExpr::Hash(ast::HashKind::Word, value.with_span(span))),
            "event" => Ok(ast::ConstantExpr::Hash(ast::HashKind::Event, value.with_span(span))),
            _ => Err(ParsingError::InvalidSyntax {
                span,
                message: format!("unsupported constant function `{name}`"),
            }),
        }
    }

    fn parse_word_literal(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        let lbracket = self.expect_kind(SyntaxKind::LBracket, "expected `[` to start word")?;
        let mut elements = [Felt::ZERO; 4];
        for (index, element) in elements.iter_mut().enumerate() {
            let value = self.parse_felt_literal()?;
            *element = Felt::new(value.as_int());
            if index < 3 {
                self.expect_kind(SyntaxKind::Comma, "expected `,` between word elements")?;
            }
        }
        let rbracket = self.expect_kind(SyntaxKind::RBracket, "expected `]` to close word")?;
        let span = join_spans(self.token_span(&lbracket), self.token_span(&rbracket));
        Ok(ast::ConstantExpr::Word(Span::new(span, WordValue(elements))))
    }

    fn parse_felt_literal(&mut self) -> Result<IntValue, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax("expected an integer literal"));
        };
        if token.kind() != SyntaxKind::Number {
            return Err(self.invalid_syntax("expected an integer literal"));
        }

        match parse_numeric_token(self.token_span(&token), token.text())? {
            ParsedNumeric::Int(value) => {
                self.bump();
                Ok(value)
            },
            ParsedNumeric::Word(_) => Err(ParsingError::InvalidSyntax {
                span: self.token_span(&token),
                message: "expected a felt-sized integer literal".to_string(),
            }),
        }
    }

    fn parse_type_expr(&mut self) -> Result<ast::TypeExpr, ParsingError> {
        if (self.at_keyword("ptr")) && self.peek_kind(1) == Some(SyntaxKind::LAngle) {
            return self.parse_pointer_type().map(ast::TypeExpr::Ptr);
        }
        if self.at_kind(SyntaxKind::LBracket) {
            return self.parse_array_type().map(ast::TypeExpr::Array);
        }
        if self.at_keyword("struct") {
            return self.parse_struct_type().map(ast::TypeExpr::Struct);
        }

        let path = self.parse_path(PathMode::Type)?;
        if let Some(name) = path.as_ident()
            && let Some(primitive) = builtin_type_for_name(name.as_str())
        {
            return Ok(ast::TypeExpr::Primitive(Span::new(path.span(), primitive)));
        }

        Ok(ast::TypeExpr::Ref(path))
    }

    fn parse_pointer_type(&mut self) -> Result<ast::PointerType, ParsingError> {
        let ptr = self.expect_keyword("ptr", "expected `ptr`")?;
        self.expect_kind(SyntaxKind::LAngle, "expected `<` after `ptr`")?;
        let pointee = self.parse_type_expr()?;

        let mut ty = ast::PointerType::new(pointee);
        if self.at_kind(SyntaxKind::Comma) {
            self.bump();
            self.expect_keyword("addrspace", "expected `addrspace` after `,`")?;
            self.expect_kind(SyntaxKind::LParen, "expected `(` after `addrspace`")?;
            let addrspace = self.parse_address_space()?;
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close `addrspace(...)`")?;
            ty = ty.with_address_space(addrspace);
        }

        let rangle = self.expect_kind(SyntaxKind::RAngle, "expected `>` to close pointer type")?;
        Ok(ty.with_span(join_spans(self.token_span(&ptr), self.token_span(&rangle))))
    }

    fn parse_array_type(&mut self) -> Result<ast::ArrayType, ParsingError> {
        let lbracket =
            self.expect_kind(SyntaxKind::LBracket, "expected `[` to start array type")?;
        let elem = self.parse_type_expr()?;
        self.expect_kind(SyntaxKind::Semicolon, "expected `;` in array type")?;
        let arity = self.parse_decimal_usize("expected an array length")?;
        let rbracket =
            self.expect_kind(SyntaxKind::RBracket, "expected `]` to close array type")?;
        Ok(ast::ArrayType::new(elem, arity)
            .with_span(join_spans(self.token_span(&lbracket), self.token_span(&rbracket))))
    }

    fn parse_struct_type(&mut self) -> Result<ast::StructType, ParsingError> {
        let struct_kw = self.expect_keyword("struct", "expected `struct`")?;
        let repr = if self.at_kind(SyntaxKind::At) {
            Some(self.parse_struct_repr()?)
        } else {
            None
        };

        self.expect_kind(SyntaxKind::LBrace, "expected `{` to start struct body")?;
        let mut fields = Vec::new();
        while !self.at_kind(SyntaxKind::RBrace) {
            fields.push(self.parse_struct_field()?);
            if self.at_kind(SyntaxKind::Comma) {
                self.bump();
                if self.at_kind(SyntaxKind::RBrace) {
                    break;
                }
            } else {
                break;
            }
        }

        let rbrace = self.expect_kind(SyntaxKind::RBrace, "expected `}` to close struct type")?;
        let mut ty = ast::StructType::new(None, fields)
            .with_span(join_spans(self.token_span(&struct_kw), self.token_span(&rbrace)));
        if let Some(repr) = repr {
            ty = ty.with_repr(repr);
        }
        Ok(ty)
    }

    fn parse_struct_field(&mut self) -> Result<ast::StructField, ParsingError> {
        let name_token = self.expect_ident("expected a struct field name")?;
        let name = self.context.lower_ident_token(&name_token)?;
        self.expect_kind(SyntaxKind::Colon, "expected `:` after struct field name")?;
        let ty = self.parse_type_expr()?;
        let span = join_spans(self.context.parse().span_for_token(&name_token), ty.span());
        Ok(ast::StructField { span, name, ty })
    }

    fn parse_struct_repr(&mut self) -> Result<Span<TypeRepr>, ParsingError> {
        let at = self.expect_kind(SyntaxKind::At, "expected `@` before struct annotation")?;
        let name = self.expect_ident("expected a struct annotation name")?;
        let name_span = self.token_span(&name);
        let name_text = name.text();

        if !self.at_kind(SyntaxKind::LParen) {
            return match name_text {
                "packed" => Ok(Span::new(name_span, TypeRepr::packed(1))),
                "transparent" => Ok(Span::new(name_span, TypeRepr::Transparent)),
                "bigendian" => Ok(Span::new(name_span, TypeRepr::BigEndian)),
                "align" => Err(ParsingError::InvalidStructRepr {
                    span: join_spans(self.token_span(&at), name_span),
                    message: "you must specify an alignment here, e.g. 'align(16)'".to_string(),
                }),
                _ => Err(ParsingError::InvalidStructAnnotation { span: name_span }),
            };
        }

        let lparen =
            self.expect_kind(SyntaxKind::LParen, "expected `(` after struct annotation")?;
        if name_text != "align" {
            let span = self.consume_balanced_suffix(
                self.context.parse().span_for_token(&at),
                SyntaxKind::LParen,
                SyntaxKind::RParen,
            )?;
            return Err(ParsingError::InvalidStructAnnotation { span });
        }

        let value = match self.current() {
            Some(token) if token.kind() == SyntaxKind::Number => {
                let token = self.bump().expect("numeric token should be present");
                self.parse_positive_alignment(&token)?
            },
            Some(token) => {
                let span = self.token_span(&token);
                let _ = self.consume_until(SyntaxKind::RParen);
                self.expect_kind(
                    SyntaxKind::RParen,
                    "expected `)` to close `align(...)` annotation",
                )?;
                return Err(ParsingError::InvalidStructRepr {
                    span,
                    message: "invalid alignment expresssion, expected an integer".to_string(),
                });
            },
            None => {
                return Err(ParsingError::InvalidStructRepr {
                    span: join_spans(self.token_span(&at), self.token_span(&lparen)),
                    message: "expected a single element in this meta list, e.g. 'align(16)'"
                        .to_string(),
                });
            },
        };

        if self.at_kind(SyntaxKind::Comma) || !self.at_kind(SyntaxKind::RParen) {
            let span = join_spans(self.context.parse().span_for_token(&at), self.current_span());
            let _ = self.consume_until(SyntaxKind::RParen);
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close `align(...)` annotation")?;
            return Err(ParsingError::InvalidStructRepr {
                span,
                message: "expected a single element in this meta list, e.g. 'align(16)'"
                    .to_string(),
            });
        }

        let rparen =
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close `align(...)` annotation")?;
        Ok(Span::new(
            join_spans(self.token_span(&at), self.token_span(&rparen)),
            TypeRepr::align(value),
        ))
    }

    fn parse_positive_alignment(&self, token: &SyntaxToken) -> Result<u16, ParsingError> {
        let span = self.token_span(token);
        let value = parse_alignment_literal(token.text(), span)?;
        if !(1..=u16::MAX as u64).contains(&value) {
            return Err(ParsingError::InvalidStructRepr {
                span,
                message: "invalid alignment, expected a value in the range 1..=65535".to_string(),
            });
        }
        Ok(value as u16)
    }

    fn parse_address_space(&mut self) -> Result<AddressSpace, ParsingError> {
        match self.bump() {
            Some(token) if token.kind() == SyntaxKind::Ident && token.text() == "byte" => {
                Ok(AddressSpace::Byte)
            },
            Some(token) if token.kind() == SyntaxKind::Ident && token.text() == "felt" => {
                Ok(AddressSpace::Element)
            },
            _ => Err(self.invalid_syntax("expected `byte` or `felt` address space")),
        }
    }

    fn parse_decimal_usize(&mut self, message: &'static str) -> Result<usize, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax(message));
        };
        if token.kind() != SyntaxKind::Number {
            return Err(self.invalid_syntax(message));
        }

        let span = self.token_span(&token);
        let Some(value) = parse_decimal_u64(token.text()) else {
            return Err(ParsingError::InvalidSyntax { span, message: message.to_string() });
        };
        self.bump();

        usize::try_from(value)
            .map_err(|_| ParsingError::ImmediateOutOfRange { span, range: 0..(u32::MAX as usize) })
    }

    fn parse_path(&mut self, mode: PathMode) -> Result<Span<Arc<Path>>, ParsingError> {
        let start_pos = self.pos;
        let absolute = if self.at_kind(SyntaxKind::ColonColon) {
            self.bump();
            true
        } else {
            false
        };

        let first = self.expect_path_component("expected a path component")?;
        let mut last = first.clone();
        let mut segments = 1usize;
        while self.at_kind(SyntaxKind::ColonColon) {
            self.bump();
            last = self.expect_path_component("expected a path component after `::`")?;
            segments += 1;
        }

        let start_span = self
            .tokens
            .get(start_pos)
            .map(|token| self.token_span(token))
            .unwrap_or_else(|| self.current_span());
        let span = join_spans(start_span, self.token_span(&last));
        if absolute && segments == 1 {
            return Err(ParsingError::UnqualifiedImport { span });
        }

        if mode == PathMode::Constant {
            self.context.lower_constant_ident_token(&last)?;
        }

        let raw = self.tokens[start_pos..self.pos]
            .iter()
            .map(|token| token.text())
            .collect::<String>();
        self.context.lower_raw_path(span, &raw)
    }

    fn expect_path_component(
        &mut self,
        message: &'static str,
    ) -> Result<SyntaxToken, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax(message));
        };

        match token.kind() {
            SyntaxKind::Ident | SyntaxKind::QuotedIdent | SyntaxKind::SpecialIdent => {
                Ok(self.bump().expect("path component token should be present"))
            },
            _ => Err(self.invalid_syntax(message)),
        }
    }

    fn lower_string_token(&mut self, token: &SyntaxToken) -> Result<ast::Ident, ParsingError> {
        let span = self.token_span(token);
        let raw = token.text().strip_prefix('"').and_then(|text| text.strip_suffix('"')).ok_or(
            ParsingError::InvalidSyntax {
                span,
                message: "expected a quoted string".to_string(),
            },
        )?;
        self.context.lower_ident_text(span, raw)
    }

    fn current_constant_operator(&self) -> Option<(u8, ast::ConstantOp)> {
        let token = self.current()?;
        match token.kind() {
            SyntaxKind::Plus => Some((1, ast::ConstantOp::Add)),
            SyntaxKind::Minus => Some((1, ast::ConstantOp::Sub)),
            SyntaxKind::Star => Some((2, ast::ConstantOp::Mul)),
            SyntaxKind::Slash => Some((2, ast::ConstantOp::Div)),
            SyntaxKind::SlashSlash => Some((2, ast::ConstantOp::IntDiv)),
            _ => None,
        }
    }

    fn expect_keyword(
        &mut self,
        keyword: &'static str,
        message: &'static str,
    ) -> Result<SyntaxToken, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax(message));
        };
        if token.kind() == SyntaxKind::Ident && token.text() == keyword {
            Ok(self.bump().expect("keyword token should be present"))
        } else {
            Err(self.invalid_syntax(message))
        }
    }

    fn expect_ident(&mut self, message: &'static str) -> Result<SyntaxToken, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax(message));
        };
        if token.kind() == SyntaxKind::Ident {
            Ok(self.bump().expect("identifier token should be present"))
        } else {
            Err(self.invalid_syntax(message))
        }
    }

    fn expect_kind(
        &mut self,
        kind: SyntaxKind,
        message: &'static str,
    ) -> Result<SyntaxToken, ParsingError> {
        let Some(token) = self.current() else {
            return Err(self.invalid_syntax(message));
        };
        if token.kind() == kind {
            Ok(self.bump().expect("token should be present"))
        } else {
            Err(self.invalid_syntax(message))
        }
    }

    fn expect_eof(&self, message: &'static str) -> Result<(), ParsingError> {
        if self.is_eof() {
            Ok(())
        } else {
            Err(self.invalid_syntax(message))
        }
    }

    fn consume_balanced_suffix(
        &mut self,
        start: SourceSpan,
        open: SyntaxKind,
        close: SyntaxKind,
    ) -> Result<SourceSpan, ParsingError> {
        let mut depth = 1usize;
        while let Some(token) = self.bump() {
            if token.kind() == open {
                depth += 1;
            } else if token.kind() == close {
                depth -= 1;
                if depth == 0 {
                    return Ok(join_spans(start, self.token_span(&token)));
                }
            }
        }

        Err(ParsingError::InvalidSyntax {
            span: start,
            message: format!("expected `{}` to close annotation", close_text(close)),
        })
    }

    fn consume_until(&mut self, kind: SyntaxKind) -> Option<SyntaxToken> {
        while let Some(token) = self.current() {
            if token.kind() == kind {
                return Some(token);
            }
            self.bump();
        }
        None
    }

    fn at_keyword(&self, keyword: &'static str) -> bool {
        matches!(self.current(), Some(token) if token.kind() == SyntaxKind::Ident && token.text() == keyword)
    }

    fn at_kind(&self, kind: SyntaxKind) -> bool {
        self.peek_kind(0) == Some(kind)
    }

    fn peek_kind(&self, offset: usize) -> Option<SyntaxKind> {
        self.tokens.get(self.pos + offset).map(SyntaxToken::kind)
    }

    fn current(&self) -> Option<SyntaxToken> {
        self.tokens.get(self.pos).cloned()
    }

    fn current_span(&self) -> SourceSpan {
        self.current()
            .map(|token| self.token_span(&token))
            .unwrap_or_else(|| SourceSpan::at(self.span.source_id(), self.span.end()))
    }

    fn invalid_syntax(&self, message: &'static str) -> ParsingError {
        ParsingError::InvalidSyntax {
            span: self.current_span(),
            message: message.to_string(),
        }
    }

    fn bump(&mut self) -> Option<SyntaxToken> {
        let token = self.tokens.get(self.pos).cloned()?;
        self.pos += 1;
        Some(token)
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn token_span(&self, token: &SyntaxToken) -> SourceSpan {
        self.context.parse().span_for_token(token)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathMode {
    Constant,
    Type,
}

enum ParsedNumeric {
    Int(IntValue),
    Word(WordValue),
}

fn builtin_type_for_name(name: &str) -> Option<Type> {
    Some(match name {
        "word" => Type::Array(Arc::new(ast::types::ArrayType::new(Type::Felt, 4))),
        "i1" => Type::I1,
        "i8" => Type::I8,
        "i16" => Type::I16,
        "i32" => Type::I32,
        "i64" => Type::I64,
        "i128" => Type::I128,
        "u8" => Type::U8,
        "u16" => Type::U16,
        "u32" => Type::U32,
        "u64" => Type::U64,
        "u128" => Type::U128,
        "felt" => Type::Felt,
        _ => return None,
    })
}

fn parse_numeric_token(span: SourceSpan, text: &str) -> Result<ParsedNumeric, ParsingError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return parse_hex_literal(span, hex);
    }
    if text.starts_with("0b") || text.starts_with("0B") {
        return Err(ParsingError::InvalidSyntax {
            span,
            message: "binary literals are not supported in constant expressions".to_string(),
        });
    }

    let value = text.parse::<u64>().map_err(|error| ParsingError::InvalidLiteral {
        span,
        kind: literal_error_from_int_error(error.kind(), LiteralErrorKind::FeltOverflow),
    })?;
    if value >= Felt::ORDER_U64 {
        return Err(ParsingError::InvalidLiteral {
            span,
            kind: LiteralErrorKind::FeltOverflow,
        });
    }

    Ok(ParsedNumeric::Int(super::super::lexer::shrink_u64_hex(value)))
}

fn parse_hex_literal(span: SourceSpan, hex_digits: &str) -> Result<ParsedNumeric, ParsingError> {
    let hex_digits = pad_hex_if_needed(hex_digits);
    match hex_digits.len() {
        len if len <= 16 && len.is_multiple_of(2) => {
            let value = u64::from_str_radix(hex_digits.as_ref(), 16).map_err(|error| {
                ParsingError::InvalidLiteral {
                    span,
                    kind: literal_error_from_int_error(
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
            Ok(ParsedNumeric::Int(super::super::lexer::shrink_u64_hex(value)))
        },
        64 => {
            let mut word = [Felt::ZERO; 4];
            for (index, element) in word.iter_mut().enumerate() {
                let offset = index * 16;
                let digits = &hex_digits[offset..(offset + 16)];
                let value = u64::from_str_radix(digits, 16).map_err(|error| {
                    ParsingError::InvalidLiteral {
                        span,
                        kind: literal_error_from_int_error(
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
                *element = Felt::new(value);
            }

            Ok(ParsedNumeric::Word(WordValue(word)))
        },
        len if len > 64 => {
            Err(ParsingError::InvalidHexLiteral { span, kind: HexErrorKind::TooLong })
        },
        _ => Err(ParsingError::InvalidHexLiteral { span, kind: HexErrorKind::Invalid }),
    }
}

fn pad_hex_if_needed(hex: &str) -> Cow<'_, str> {
    if hex.len().is_multiple_of(2) {
        Cow::Borrowed(hex)
    } else {
        let mut padded = String::with_capacity(hex.len() + 1);
        padded.push('0');
        padded.push_str(hex);
        Cow::Owned(padded)
    }
}

fn parse_alignment_literal(text: &str, span: SourceSpan) -> Result<u64, ParsingError> {
    match parse_numeric_token(span, text)? {
        ParsedNumeric::Int(value) => Ok(value.as_int()),
        ParsedNumeric::Word(_) => Err(ParsingError::InvalidStructRepr {
            span,
            message: "invalid alignment expresssion, expected an integer".to_string(),
        }),
    }
}

fn parse_decimal_u64(text: &str) -> Option<u64> {
    if text.starts_with("0x")
        || text.starts_with("0X")
        || text.starts_with("0b")
        || text.starts_with("0B")
    {
        None
    } else {
        text.parse::<u64>().ok()
    }
}

fn literal_error_from_int_error(
    kind: &core::num::IntErrorKind,
    overflow: LiteralErrorKind,
) -> LiteralErrorKind {
    match kind {
        core::num::IntErrorKind::Empty => LiteralErrorKind::Empty,
        core::num::IntErrorKind::InvalidDigit => LiteralErrorKind::InvalidDigit,
        core::num::IntErrorKind::PosOverflow | core::num::IntErrorKind::NegOverflow => overflow,
        core::num::IntErrorKind::Zero => LiteralErrorKind::InvalidDigit,
        _ => overflow,
    }
}

fn join_spans(start: SourceSpan, end: SourceSpan) -> SourceSpan {
    SourceSpan::new(start.source_id(), start.start()..end.end())
}

fn close_text(kind: SyntaxKind) -> &'static str {
    match kind {
        SyntaxKind::RParen => ")",
        SyntaxKind::RBrace => "}",
        SyntaxKind::RBracket => "]",
        SyntaxKind::RAngle => ">",
        _ => "token",
    }
}
