use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use miden_assembly_syntax_cst::{
    SyntaxKind, SyntaxToken,
    ast::{
        AdviceMap as CstAdviceMap, AstNode, Attribute as CstAttribute, Expr as CstExpr,
        Signature as CstSignature, TypeBody as CstTypeBody,
    },
};
use miden_core::{Felt, field::PrimeField64};
use miden_debug_types::{SourceSpan, Span, Spanned};

use super::context::LoweringContext;
use crate::{
    Path,
    ast::{
        self, PathBuf,
        types::{AddressSpace, Type, TypeRepr},
    },
    parser::{BinErrorKind, HexErrorKind, IntValue, LiteralErrorKind, ParsingError, WordValue},
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

pub(super) fn lower_enum_decl_from_body(
    context: &mut LoweringContext<'_>,
    visibility: ast::Visibility,
    name: ast::Ident,
    body: &CstTypeBody,
    span: SourceSpan,
) -> Result<ast::EnumType, ParsingError> {
    let tokens = significant_tokens(body.syntax());
    let mut parser = FragmentParser::new(context, tokens, span);
    let enum_ty = parser.parse_enum_decl(visibility, name, span)?;
    parser.expect_eof("unexpected trailing tokens in enum declaration")?;
    Ok(enum_ty)
}

pub(super) fn lower_function_type_from_signature(
    context: &mut LoweringContext<'_>,
    signature: &CstSignature,
) -> Result<ast::FunctionType, ParsingError> {
    let span = context.parse().span_for_node(signature.syntax());
    let tokens = significant_tokens(signature.syntax());
    let mut parser = FragmentParser::new(context, tokens, span);
    let ty = parser.parse_function_type()?;
    parser.expect_eof("unexpected trailing tokens in procedure signature")?;
    Ok(ty)
}

pub(super) fn lower_u32_immediate_token(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<ast::ImmU32, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(ast::Immediate::Constant(context.lower_constant_ident_token(token)?))
        },
        SyntaxKind::Number => {
            let value = parse_u32_literal(span, token.text())?;
            Ok(ast::Immediate::Value(Span::new(span, value)))
        },
        _ => Err(ParsingError::InvalidSyntax {
            span,
            message: "expected a u32 literal or constant reference".to_string(),
        }),
    }
}

pub(super) fn lower_attribute(
    context: &mut LoweringContext<'_>,
    attribute: &CstAttribute,
) -> Result<ast::Attribute, ParsingError> {
    let span = context.parse().span_for_node(attribute.syntax());
    let tokens = significant_tokens(attribute.syntax());
    let mut parser = FragmentParser::new(context, tokens, span);
    let attribute = parser.parse_attribute()?;
    parser.expect_eof("unexpected trailing tokens in attribute")?;
    Ok(attribute)
}

pub(super) fn lower_advice_map_decl(
    context: &mut LoweringContext<'_>,
    advice_map: &CstAdviceMap,
) -> Result<ast::AdviceMapEntry, ParsingError> {
    let span = context.parse().span_for_node(advice_map.syntax());
    let tokens = significant_tokens_recursive(advice_map.syntax());
    let mut parser = FragmentParser::new(context, tokens, span);
    let entry = parser.parse_advice_map_decl(span)?;
    parser.expect_eof("unexpected trailing tokens in advice-map declaration")?;
    Ok(entry)
}

fn significant_tokens(node: &miden_assembly_syntax_cst::syntax::SyntaxNode) -> Vec<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

fn significant_tokens_recursive(
    node: &miden_assembly_syntax_cst::syntax::SyntaxNode,
) -> Vec<SyntaxToken> {
    node.descendants_with_tokens()
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

    fn parse_constant_arithmetic_expr(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        if self.is_eof() {
            return Err(self.invalid_syntax("expected a constant expression"));
        }
        self.parse_constant_arithmetic_expr_bp(0)
    }

    fn parse_constant_arithmetic_expr_bp(
        &mut self,
        min_precedence: u8,
    ) -> Result<ast::ConstantExpr, ParsingError> {
        let mut lhs = self.parse_numeric_constant_term()?;
        while let Some((precedence, op)) = self.current_constant_operator() {
            if precedence < min_precedence {
                break;
            }

            self.bump();
            let rhs = self.parse_constant_arithmetic_expr_bp(precedence + 1)?;
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

    fn parse_numeric_constant_term(&mut self) -> Result<ast::ConstantExpr, ParsingError> {
        if self.at_kind(SyntaxKind::LParen) {
            self.bump();
            let expr = self.parse_constant_arithmetic_expr()?;
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close constant expression")?;
            return Ok(expr);
        }

        if self.at_kind(SyntaxKind::LBracket)
            || ((self.at_keyword("word") || self.at_keyword("event"))
                && self.peek_kind(1) == Some(SyntaxKind::LParen))
            || matches!(
                self.current().as_ref().map(SyntaxToken::kind),
                Some(SyntaxKind::QuotedString | SyntaxKind::QuotedIdent)
            )
        {
            return Err(self.invalid_syntax("expected an integer literal or constant reference"));
        }

        let Some(token) = self.current() else {
            return Err(self.invalid_syntax("expected an integer literal or constant reference"));
        };

        match token.kind() {
            SyntaxKind::Number => match parse_numeric_token(self.token_span(&token), token.text())?
            {
                ParsedNumeric::Int(value) => {
                    self.bump();
                    Ok(ast::ConstantExpr::Int(Span::new(self.token_span(&token), value)))
                },
                ParsedNumeric::Word(_) => Err(ParsingError::InvalidSyntax {
                    span: self.token_span(&token),
                    message: "expected an integer literal or constant reference".to_string(),
                }),
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

    fn parse_function_type(&mut self) -> Result<ast::FunctionType, ParsingError> {
        let lparen =
            self.expect_kind(SyntaxKind::LParen, "expected `(` to start procedure signature")?;
        let args = self.parse_comma_delimited_allow_trailing(
            SyntaxKind::RParen,
            Self::parse_function_param_type,
        )?;
        let rparen =
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close procedure parameters")?;
        let mut end_span = self.token_span(&rparen);
        let results = if self.at_kind(SyntaxKind::RArrow) {
            self.bump();
            let results = self.parse_function_result_types()?;
            if let Some(last) = self.last_consumed_span() {
                end_span = last;
            }
            results
        } else {
            Vec::new()
        };

        Ok(ast::FunctionType::new(ast::types::CallConv::Fast, args, results)
            .with_span(join_spans(self.token_span(&lparen), end_span)))
    }

    fn parse_function_param_type(&mut self) -> Result<ast::TypeExpr, ParsingError> {
        if !matches!(self.current().as_ref().map(SyntaxToken::kind), Some(SyntaxKind::Ident))
            || self.peek_kind(1) != Some(SyntaxKind::Colon)
        {
            return Err(self.invalid_syntax("expected a named procedure parameter"));
        }

        self.bump();
        self.bump();
        self.parse_type_expr()
    }

    fn parse_function_result_types(&mut self) -> Result<Vec<ast::TypeExpr>, ParsingError> {
        if self.at_kind(SyntaxKind::LParen) {
            self.bump();
            let results = self.parse_comma_delimited_allow_trailing(
                SyntaxKind::RParen,
                Self::parse_maybe_named_result_type,
            )?;
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close procedure results")?;
            Ok(results)
        } else {
            Ok(vec![self.parse_type_expr()?])
        }
    }

    fn parse_maybe_named_result_type(&mut self) -> Result<ast::TypeExpr, ParsingError> {
        if matches!(self.current().as_ref().map(SyntaxToken::kind), Some(SyntaxKind::Ident))
            && self.peek_kind(1) == Some(SyntaxKind::Colon)
        {
            self.bump();
            self.bump();
        }
        self.parse_type_expr()
    }

    fn parse_attribute(&mut self) -> Result<ast::Attribute, ParsingError> {
        self.expect_kind(SyntaxKind::At, "expected `@` to start an attribute")?;
        let name_token = self.expect_ident("expected an attribute name")?;
        let name = self.context.lower_ident_token(&name_token)?;

        let attribute = if self.at_kind(SyntaxKind::LParen) {
            self.bump();
            if self.at_kind(SyntaxKind::RParen) {
                return Err(self.invalid_syntax("expected attribute metadata"));
            }

            let has_key_value = self.has_top_level_equals_before(SyntaxKind::RParen);
            let attribute = if has_key_value {
                let items = self.parse_comma_delimited(SyntaxKind::RParen, Self::parse_meta_kv)?;
                let mut map = BTreeMap::<ast::Ident, ast::MetaExpr>::default();
                for (pair_span, key, value) in items {
                    use alloc::collections::btree_map::Entry;

                    match map.entry(key) {
                        Entry::Vacant(entry) => {
                            entry.insert(value);
                        },
                        Entry::Occupied(entry) => {
                            return Err(ParsingError::AttributeKeyValueConflict {
                                span: pair_span,
                                prev: entry.key().span(),
                            });
                        },
                    }
                }
                ast::Attribute::KeyValue(ast::MetaKeyValue::new(name, map))
            } else {
                let items =
                    self.parse_comma_delimited(SyntaxKind::RParen, Self::parse_meta_expr)?;
                ast::Attribute::List(ast::MetaList::new(name, items))
            };
            self.expect_kind(SyntaxKind::RParen, "expected `)` to close attribute metadata")?;
            attribute
        } else {
            ast::Attribute::Marker(name)
        };

        Ok(attribute.with_span(self.span))
    }

    fn parse_meta_kv(&mut self) -> Result<(SourceSpan, ast::Ident, ast::MetaExpr), ParsingError> {
        let key_token = self.expect_ident("expected an attribute key")?;
        let key = self.context.lower_ident_token(&key_token)?;
        self.expect_kind(SyntaxKind::Equal, "expected `=` in attribute metadata")?;
        let value = self.parse_meta_expr()?;
        Ok((join_spans(key.span(), value.span()), key, value))
    }

    fn parse_meta_expr(&mut self) -> Result<ast::MetaExpr, ParsingError> {
        if self.at_kind(SyntaxKind::LBracket) {
            return self.parse_word_value_literal().map(ast::MetaExpr::Word);
        }

        let Some(token) = self.current() else {
            return Err(self.invalid_syntax("expected an attribute metadata value"));
        };

        match token.kind() {
            SyntaxKind::Ident => {
                let token = self.bump().expect("current token should exist");
                Ok(ast::MetaExpr::Ident(self.context.lower_ident_token(&token)?))
            },
            SyntaxKind::QuotedString | SyntaxKind::QuotedIdent => {
                let token = self.bump().expect("current token should exist");
                Ok(ast::MetaExpr::String(self.lower_string_token(&token)?))
            },
            SyntaxKind::Number => match parse_numeric_token(self.token_span(&token), token.text())?
            {
                ParsedNumeric::Int(value) => {
                    self.bump();
                    Ok(ast::MetaExpr::Int(Span::new(self.token_span(&token), value)))
                },
                ParsedNumeric::Word(value) => {
                    self.bump();
                    Ok(ast::MetaExpr::Word(Span::new(self.token_span(&token), value)))
                },
            },
            _ => Err(self.invalid_syntax("expected an attribute metadata value")),
        }
    }

    fn parse_advice_map_decl(
        &mut self,
        span: SourceSpan,
    ) -> Result<ast::AdviceMapEntry, ParsingError> {
        self.expect_keyword("adv_map", "expected `adv_map` in advice-map declaration")?;
        let name_token = self.expect_ident("expected an advice-map name")?;
        let name = self.context.lower_constant_ident_token(&name_token)?;
        let key = if self.at_kind(SyntaxKind::LParen) {
            let lparen = self.bump().expect("`(` should be present");
            let value = self.parse_word_value()?;
            let rparen =
                self.expect_kind(SyntaxKind::RParen, "expected `)` to close advice-map key")?;
            Some(Span::new(join_spans(self.token_span(&lparen), self.token_span(&rparen)), value))
        } else {
            None
        };

        self.expect_kind(SyntaxKind::Equal, "expected `=` in advice-map declaration")?;
        self.expect_kind(SyntaxKind::LBracket, "expected `[` to start advice-map values")?;
        let value = self.parse_comma_delimited(SyntaxKind::RBracket, Self::parse_felt)?;
        self.expect_kind(SyntaxKind::RBracket, "expected `]` to close advice-map values")?;

        Ok(ast::AdviceMapEntry::new(span, name, key, value))
    }

    fn parse_word_value(&mut self) -> Result<WordValue, ParsingError> {
        if self.at_kind(SyntaxKind::LBracket) {
            return self.parse_word_value_literal().map(Span::into_inner);
        }

        let Some(token) = self.current() else {
            return Err(ParsingError::InvalidAdvMapKey { span: self.current_span() });
        };
        if token.kind() != SyntaxKind::Number {
            return Err(ParsingError::InvalidAdvMapKey { span: self.token_span(&token) });
        }

        match parse_numeric_token(self.token_span(&token), token.text())? {
            ParsedNumeric::Word(value) => {
                self.bump();
                Ok(value)
            },
            ParsedNumeric::Int(_) => {
                Err(ParsingError::InvalidAdvMapKey { span: self.token_span(&token) })
            },
        }
    }

    fn parse_word_value_literal(&mut self) -> Result<Span<WordValue>, ParsingError> {
        match self.parse_word_literal()? {
            ast::ConstantExpr::Word(value) => Ok(value),
            _ => unreachable!("word literal parser should produce a word"),
        }
    }

    fn parse_felt(&mut self) -> Result<Felt, ParsingError> {
        let value = self.parse_felt_literal()?;
        Ok(Felt::new(value.as_int()))
    }

    fn parse_enum_decl(
        &mut self,
        visibility: ast::Visibility,
        name: ast::Ident,
        span: SourceSpan,
    ) -> Result<ast::EnumType, ParsingError> {
        self.expect_kind(SyntaxKind::Colon, "expected `:` in enum declaration")?;
        let repr = self.parse_enum_repr()?;
        self.expect_kind(SyntaxKind::LBrace, "expected `{` to start enum body")?;
        let variants = self.parse_enum_variants()?;
        self.expect_kind(SyntaxKind::RBrace, "expected `}` to close enum declaration")?;
        Ok(ast::EnumType::new(visibility, name, repr, variants).with_span(span))
    }

    fn parse_enum_repr(&mut self) -> Result<Type, ParsingError> {
        let token = self.expect_ident("expected an integral or felt enum representation type")?;
        let span = self.token_span(&token);
        match token.text() {
            "i1" => Ok(Type::I1),
            "i8" => Ok(Type::I8),
            "i16" => Ok(Type::I16),
            "i32" => Ok(Type::I32),
            "i64" => Ok(Type::I64),
            "i128" => Ok(Type::I128),
            "u8" => Ok(Type::U8),
            "u16" => Ok(Type::U16),
            "u32" => Ok(Type::U32),
            "u64" => Ok(Type::U64),
            "u128" => Ok(Type::U128),
            "felt" => Ok(Type::Felt),
            _ => Err(ParsingError::InvalidSyntax {
                span,
                message: "expected an integral or felt enum representation type".to_string(),
            }),
        }
    }

    fn parse_enum_variants(&mut self) -> Result<Vec<ast::Variant>, ParsingError> {
        let mut variants = Vec::new();
        let mut next = ast::ConstantExpr::Int(Span::new(self.span, IntValue::U8(0)));

        while !self.at_kind(SyntaxKind::RBrace) {
            let name_token = self.expect_ident("expected an enum variant name")?;
            let name_span = self.token_span(&name_token);
            let name = self.context.lower_constant_ident_token(&name_token)?;

            let (variant, next_expr) = if self.at_kind(SyntaxKind::Equal) {
                self.bump();
                let discriminant = self.parse_constant_arithmetic_expr()?;
                let variant_span = join_spans(name_span, discriminant.span());
                (
                    ast::Variant::new(name.clone(), discriminant, None).with_span(variant_span),
                    self.next_enum_discriminant_expr(name.clone(), variant_span),
                )
            } else {
                (
                    ast::Variant::new(name.clone(), next, None).with_span(name_span),
                    self.next_enum_discriminant_expr(name.clone(), name_span),
                )
            };
            next = next_expr;
            variants.push(variant);

            if self.at_kind(SyntaxKind::Comma) {
                self.bump();
                if self.at_kind(SyntaxKind::RBrace) {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(variants)
    }

    fn next_enum_discriminant_expr(&self, name: ast::Ident, span: SourceSpan) -> ast::ConstantExpr {
        ast::ConstantExpr::BinaryOp {
            span,
            op: ast::ConstantOp::Add,
            lhs: Box::new(ast::ConstantExpr::Var(Span::new(span, PathBuf::from(name).into()))),
            rhs: Box::new(ast::ConstantExpr::Int(Span::new(span, IntValue::U8(1)))),
        }
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
        Ok(self.context.lower_string_text(span, raw))
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

    fn last_consumed_span(&self) -> Option<SourceSpan> {
        self.pos
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index))
            .map(|token| self.token_span(token))
    }

    fn parse_comma_delimited_allow_trailing<T>(
        &mut self,
        terminator: SyntaxKind,
        mut parse_item: impl FnMut(&mut Self) -> Result<T, ParsingError>,
    ) -> Result<Vec<T>, ParsingError> {
        let mut items = Vec::new();
        if self.at_kind(terminator) {
            return Ok(items);
        }

        loop {
            items.push(parse_item(self)?);
            if self.at_kind(SyntaxKind::Comma) {
                self.bump();
                if self.at_kind(terminator) {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(items)
    }

    fn parse_comma_delimited<T>(
        &mut self,
        terminator: SyntaxKind,
        mut parse_item: impl FnMut(&mut Self) -> Result<T, ParsingError>,
    ) -> Result<Vec<T>, ParsingError> {
        if self.at_kind(terminator) {
            return Err(self.invalid_syntax("expected at least one item"));
        }

        let mut items = Vec::new();
        loop {
            items.push(parse_item(self)?);
            if self.at_kind(SyntaxKind::Comma) {
                self.bump();
                if self.at_kind(terminator) {
                    return Err(self.invalid_syntax("unexpected trailing comma"));
                }
            } else {
                break;
            }
        }

        Ok(items)
    }

    fn has_top_level_equals_before(&self, terminator: SyntaxKind) -> bool {
        let mut index = self.pos;
        let mut depth = 0usize;
        while let Some(token) = self.tokens.get(index) {
            match token.kind() {
                kind if depth == 0 && kind == terminator => return false,
                SyntaxKind::Equal if depth == 0 => return true,
                SyntaxKind::LParen
                | SyntaxKind::LBracket
                | SyntaxKind::LBrace
                | SyntaxKind::LAngle => {
                    depth += 1;
                },
                SyntaxKind::RParen
                | SyntaxKind::RBracket
                | SyntaxKind::RBrace
                | SyntaxKind::RAngle => {
                    depth = depth.saturating_sub(1);
                },
                _ => {},
            }
            index += 1;
        }
        false
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

pub(super) enum ParsedNumeric {
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

pub(super) fn parse_numeric_token(
    span: SourceSpan,
    text: &str,
) -> Result<ParsedNumeric, ParsingError> {
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
                let mut felt_bytes = [0u8; 8];
                for (byte_idx, byte) in felt_bytes.iter_mut().enumerate() {
                    let byte_str = &digits[(byte_idx * 2)..((byte_idx * 2) + 2)];
                    *byte = u8::from_str_radix(byte_str, 16).map_err(|error| {
                        ParsingError::InvalidLiteral {
                            span,
                            kind: literal_error_from_int_error(
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

pub(super) fn parse_decimal_u64(text: &str) -> Option<u64> {
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

fn parse_u32_literal(span: SourceSpan, text: &str) -> Result<u32, ParsingError> {
    if let Some(bin_digits) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        if bin_digits.len() > 32 {
            return Err(ParsingError::InvalidBinaryLiteral { span, kind: BinErrorKind::TooLong });
        }

        let value =
            u32::from_str_radix(bin_digits, 2).map_err(|error| ParsingError::InvalidLiteral {
                span,
                kind: literal_error_from_int_error(error.kind(), LiteralErrorKind::U32Overflow),
            })?;
        return Ok(value);
    }

    match parse_numeric_token(span, text)? {
        ParsedNumeric::Int(value) => match value {
            IntValue::U8(value) => Ok(value as u32),
            IntValue::U16(value) => Ok(value as u32),
            IntValue::U32(value) => Ok(value),
            IntValue::Felt(_) => Err(ParsingError::InvalidLiteral {
                span,
                kind: LiteralErrorKind::U32Overflow,
            }),
        },
        ParsedNumeric::Word(_) => Err(ParsingError::InvalidLiteral {
            span,
            kind: LiteralErrorKind::U32Overflow,
        }),
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

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeSet, string::ToString, sync::Arc};

    use miden_assembly_syntax_cst::{
        ast::{AstNode, Item as CstItem, SourceFile as CstSourceFile},
        parse_source_file,
    };
    use miden_debug_types::{SourceFile, SourceId, SourceLanguage, Uri};
    use pretty_assertions::assert_eq;

    use super::{
        lower_advice_map_decl, lower_attribute, lower_function_type_from_signature,
        lower_type_expr_from_alias_body,
    };
    use crate::{ast, parser::cst_lowering::context::LoweringContext};

    #[test]
    fn lowers_procedure_signatures_from_cst_tokens() {
        let source = test_source_file(
            "\
pub proc foo(a: felt, b: ptr<u8, addrspace(byte)>) -> (ok: i1, value: [u32; 4])
    nop
end
",
        );
        let parse = parse_source_file(source.clone());
        assert!(parse.diagnostics().is_empty(), "unexpected CST diagnostics");

        let source_file = CstSourceFile::cast(parse.syntax()).expect("source file");
        let procedure = source_file
            .items()
            .find_map(|item| match item {
                CstItem::Procedure(procedure) => Some(procedure),
                _ => None,
            })
            .expect("procedure");
        let signature = procedure.signature().expect("signature");

        let mut interned = BTreeSet::default();
        let mut context = LoweringContext::new(source, parse, &mut interned);
        let signature = lower_function_type_from_signature(&mut context, &signature)
            .expect("signature lowering should succeed");

        assert_eq!(
            signature,
            ast::FunctionType::new(
                ast::types::CallConv::Fast,
                vec![
                    ast::TypeExpr::Primitive(miden_debug_types::Span::unknown(
                        ast::types::Type::Felt
                    )),
                    ast::TypeExpr::Ptr(
                        ast::PointerType::new(ast::TypeExpr::Primitive(
                            miden_debug_types::Span::unknown(ast::types::Type::U8),
                        ))
                        .with_address_space(ast::types::AddressSpace::Byte),
                    ),
                ],
                vec![
                    ast::TypeExpr::Primitive(miden_debug_types::Span::unknown(
                        ast::types::Type::I1
                    )),
                    ast::TypeExpr::Array(ast::ArrayType::new(
                        ast::TypeExpr::Primitive(miden_debug_types::Span::unknown(
                            ast::types::Type::U32
                        )),
                        4,
                    )),
                ],
            )
        );
    }

    #[test]
    fn lowers_named_type_alias_bodies_from_cst_tokens() {
        let source =
            test_source_file("type Point = struct { x: u32, y: ptr<u8, addrspace(byte)> }\n");
        let parse = parse_source_file(source.clone());
        assert!(parse.diagnostics().is_empty(), "unexpected CST diagnostics");

        let source_file = CstSourceFile::cast(parse.syntax()).expect("source file");
        let type_decl = source_file
            .items()
            .find_map(|item| match item {
                CstItem::TypeDecl(type_decl) => Some(type_decl),
                _ => None,
            })
            .expect("type decl");
        let body = type_decl.body().expect("type body");

        let mut interned = BTreeSet::default();
        let mut context = LoweringContext::new(source, parse, &mut interned);
        let ty = lower_type_expr_from_alias_body(&mut context, &body)
            .expect("type lowering should succeed");

        assert_eq!(
            ty,
            ast::TypeExpr::Struct(ast::StructType::new(
                None,
                [
                    ast::StructField {
                        span: miden_debug_types::SourceSpan::UNKNOWN,
                        name: ast::Ident::new("x").unwrap(),
                        ty: ast::TypeExpr::Primitive(miden_debug_types::Span::unknown(
                            ast::types::Type::U32,
                        )),
                    },
                    ast::StructField {
                        span: miden_debug_types::SourceSpan::UNKNOWN,
                        name: ast::Ident::new("y").unwrap(),
                        ty: ast::TypeExpr::Ptr(
                            ast::PointerType::new(ast::TypeExpr::Primitive(
                                miden_debug_types::Span::unknown(ast::types::Type::U8),
                            ))
                            .with_address_space(ast::types::AddressSpace::Byte),
                        ),
                    },
                ],
            ))
        );
    }

    #[test]
    fn lowers_attributes_from_cst_tokens() {
        let source = test_source_file(
            "\
@storage(offset = 1, size = [0, 1, 2, 3])
proc foo
    nop
end
",
        );
        let parse = parse_source_file(source.clone());
        assert!(parse.diagnostics().is_empty(), "unexpected CST diagnostics");

        let source_file = CstSourceFile::cast(parse.syntax()).expect("source file");
        let procedure = source_file
            .items()
            .find_map(|item| match item {
                CstItem::Procedure(procedure) => Some(procedure),
                _ => None,
            })
            .expect("procedure");
        let attribute = procedure.attributes().next().expect("attribute");

        let mut interned = BTreeSet::default();
        let mut context = LoweringContext::new(source, parse, &mut interned);
        let attribute =
            lower_attribute(&mut context, &attribute).expect("attribute lowering should succeed");

        let ast::Attribute::KeyValue(attribute) = attribute else {
            panic!("expected key-value attribute");
        };
        assert_eq!(attribute.name(), "storage");
        let offset = attribute
            .iter()
            .find(|(key, _)| key.as_str() == "offset")
            .map(|(_, value)| value)
            .expect("offset entry");
        assert!(matches!(
            offset,
            ast::MetaExpr::Int(value) if matches!(value.inner(), crate::parser::IntValue::U8(1))
        ));
        let size = attribute
            .iter()
            .find(|(key, _)| key.as_str() == "size")
            .map(|(_, value)| value)
            .expect("size entry");
        assert!(matches!(
            size,
            ast::MetaExpr::Word(value)
                if *value.inner()
                    == crate::parser::WordValue([
                miden_core::Felt::ZERO,
                miden_core::Felt::new(1),
                miden_core::Felt::new(2),
                miden_core::Felt::new(3),
            ])
        ));
    }

    #[test]
    fn lowers_advice_map_decls_from_cst_tokens() {
        let source = test_source_file("adv_map TABLE([1, 2, 3, 4]) = [5, 6, 7]\n");
        let parse = parse_source_file(source.clone());
        assert!(parse.diagnostics().is_empty(), "unexpected CST diagnostics");

        let source_file = CstSourceFile::cast(parse.syntax()).expect("source file");
        let advice_map = source_file
            .items()
            .find_map(|item| match item {
                CstItem::AdviceMap(advice_map) => Some(advice_map),
                _ => None,
            })
            .expect("advice map");

        let mut interned = BTreeSet::default();
        let mut context = LoweringContext::new(source, parse, &mut interned);
        let entry = lower_advice_map_decl(&mut context, &advice_map)
            .expect("advice-map lowering should succeed");

        assert_eq!(entry.name.as_str(), "TABLE");
        assert_eq!(
            entry.key.as_ref().map(|word| *word.inner()),
            Some(crate::parser::WordValue([
                miden_core::Felt::new(1),
                miden_core::Felt::new(2),
                miden_core::Felt::new(3),
                miden_core::Felt::new(4),
            ]))
        );
        assert_eq!(
            entry.value,
            vec![miden_core::Felt::new(5), miden_core::Felt::new(6), miden_core::Felt::new(7),]
        );
    }

    fn test_source_file(source: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new(
            SourceId::UNKNOWN,
            SourceLanguage::Masm,
            Uri::new("memory:///cst-fragments-test.masm"),
            source.to_string().into_boxed_str(),
        ))
    }
}
