use rowan::GreenNodeBuilder;

use crate::{
    diagnostics::Diagnostic,
    lexer::{Token, tokenize},
    syntax::{SyntaxKind, SyntaxNode},
};

#[derive(Debug, Clone)]
pub struct Parse {
    green_node: rowan::GreenNode,
    diagnostics: Vec<Diagnostic>,
}

impl Parse {
    pub fn syntax(&self) -> SyntaxNode {
        SyntaxNode::new_root(self.green_node.clone())
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

pub fn parse_text(input: &str) -> Parse {
    Parser::new(input).parse()
}

struct Parser<'input> {
    tokens: Vec<Token<'input>>,
    pos: usize,
    builder: GreenNodeBuilder<'static>,
    diagnostics: Vec<Diagnostic>,
    input_len: usize,
    module_doc_emitted: bool,
    seen_non_doc_form: bool,
}

#[derive(Default, Debug, Clone, Copy)]
struct Nesting {
    parens: usize,
    brackets: usize,
    braces: usize,
}

impl Nesting {
    fn is_root(self) -> bool {
        self.parens == 0 && self.brackets == 0 && self.braces == 0
    }

    fn bump(self, kind: SyntaxKind) -> Self {
        let mut next = self;
        match kind {
            SyntaxKind::LParen => next.parens += 1,
            SyntaxKind::LBracket => next.brackets += 1,
            SyntaxKind::LBrace => next.braces += 1,
            SyntaxKind::RParen => next.parens = next.parens.saturating_sub(1),
            SyntaxKind::RBracket => next.brackets = next.brackets.saturating_sub(1),
            SyntaxKind::RBrace => next.braces = next.braces.saturating_sub(1),
            _ => (),
        }
        next
    }
}

impl<'input> Parser<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            tokens: tokenize(input),
            pos: 0,
            builder: GreenNodeBuilder::new(),
            diagnostics: Vec::new(),
            input_len: input.len(),
            module_doc_emitted: false,
            seen_non_doc_form: false,
        }
    }

    fn parse(mut self) -> Parse {
        self.start_node(SyntaxKind::SourceFile);
        while !self.eof() {
            self.parse_source_item();
        }
        self.finish_node();

        Parse {
            green_node: self.builder.finish(),
            diagnostics: self.diagnostics,
        }
    }

    fn parse_source_item(&mut self) {
        if self.at_kind(SyntaxKind::DocComment) {
            self.parse_doc_form();
            return;
        }

        if self.at_regular_trivia() {
            self.bump();
            return;
        }

        if self.at_kind(SyntaxKind::At)
            || self.at_keyword("proc")
            || self.at_prefixed_keyword("pub", "proc")
        {
            self.seen_non_doc_form = true;
            self.parse_procedure();
            return;
        }

        if self.at_keyword("begin") {
            self.seen_non_doc_form = true;
            self.parse_begin_block();
            return;
        }

        if self.at_keyword("use") || self.at_prefixed_keyword("pub", "use") {
            self.seen_non_doc_form = true;
            self.parse_import();
            return;
        }

        if self.at_keyword("const") || self.at_prefixed_keyword("pub", "const") {
            self.seen_non_doc_form = true;
            self.parse_constant();
            return;
        }

        if self.at_keyword("type")
            || self.at_keyword("enum")
            || self.at_prefixed_keyword("pub", "type")
            || self.at_prefixed_keyword("pub", "enum")
        {
            self.seen_non_doc_form = true;
            self.parse_type_decl();
            return;
        }

        if self.at_keyword("adv_map") {
            self.seen_non_doc_form = true;
            self.parse_advice_map();
            return;
        }

        self.start_node(SyntaxKind::Error);
        self.error_here("unexpected top-level token");
        self.bump();
        self.finish_node();
    }

    fn parse_doc_form(&mut self) {
        let kind = if !self.module_doc_emitted && !self.seen_non_doc_form {
            self.module_doc_emitted = true;
            SyntaxKind::ModuleDoc
        } else {
            SyntaxKind::Doc
        };

        self.start_node(kind);
        self.bump();
        self.finish_node();
    }

    fn parse_import(&mut self) {
        self.start_node(SyntaxKind::Import);

        if self.at_keyword("pub") {
            self.parse_visibility();
        }

        self.expect_keyword("use", "expected `use` in import declaration");
        self.bump_regular_trivia();
        self.parse_import_target();

        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::RArrow) {
            self.bump();
            self.bump_regular_trivia();
            if self.at_name_like() || self.at_keyword_like() {
                self.bump();
            } else {
                self.error_here("expected an alias name after `->`");
            }
        }

        self.parse_line_tail();
        self.finish_node();
    }

    fn parse_constant(&mut self) {
        self.start_node(SyntaxKind::Constant);

        if self.at_keyword("pub") {
            self.parse_visibility();
        }

        self.expect_keyword("const", "expected `const` in constant declaration");
        self.bump_regular_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected a constant name");
        }

        self.expect_kind(SyntaxKind::Equal, "expected `=` in constant declaration");
        self.parse_expr_until_line_end();
        self.parse_line_tail();
        self.finish_node();
    }

    fn parse_type_decl(&mut self) {
        self.start_node(SyntaxKind::TypeDecl);

        if self.at_keyword("pub") {
            self.parse_visibility();
        }

        self.bump_regular_trivia();
        if self.at_keyword("type") || self.at_keyword("enum") {
            self.bump();
        } else {
            self.error_here("expected `type` or `enum`");
            self.finish_node();
            return;
        }

        self.bump_regular_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected a type name");
        }

        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::Equal) || self.at_kind(SyntaxKind::Colon) {
            self.parse_type_body();
        } else {
            self.error_here("expected `=` or `:` in type declaration");
        }

        self.finish_node();
    }

    fn parse_advice_map(&mut self) {
        self.start_node(SyntaxKind::AdviceMap);
        self.expect_keyword("adv_map", "expected `adv_map`");
        self.bump_regular_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected an advice-map name");
        }

        self.bump_inline_whitespace();
        if self.at_kind(SyntaxKind::LParen) {
            self.parse_balanced_group(
                SyntaxKind::LParen,
                SyntaxKind::RParen,
                "expected `)` to close advice-map key",
            );
        }

        self.expect_kind(SyntaxKind::Equal, "expected `=` in advice-map declaration");
        self.parse_expr_until_line_end();
        self.parse_line_tail();
        self.finish_node();
    }

    fn parse_import_target(&mut self) {
        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::Number) {
            self.bump();
            return;
        }

        self.parse_path();
    }

    fn parse_path(&mut self) {
        self.start_node(SyntaxKind::Path);
        if self.at_kind(SyntaxKind::ColonColon) {
            self.bump();
        }

        self.bump_regular_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected an import path");
            self.finish_node();
            return;
        }

        loop {
            self.bump_regular_trivia();
            if !self.at_kind(SyntaxKind::ColonColon) {
                break;
            }

            self.bump();
            self.bump_regular_trivia();
            if self.at_name_like() || self.at_keyword_like() {
                self.bump();
            } else {
                self.error_here("expected a path segment after `::`");
                break;
            }
        }

        self.finish_node();
    }

    fn parse_expr_until_line_end(&mut self) {
        self.bump_regular_trivia();
        self.start_node(SyntaxKind::Expr);

        let mut nesting = Nesting::default();
        while !self.eof() {
            let kind = self.current_kind().expect("not eof");
            if nesting.is_root() && matches!(kind, SyntaxKind::Comment | SyntaxKind::DocComment) {
                break;
            }
            if nesting.is_root() && kind == SyntaxKind::Newline {
                break;
            }

            nesting = nesting.bump(kind);
            self.bump();
        }

        self.finish_node();
    }

    fn parse_type_body(&mut self) {
        self.start_node(SyntaxKind::TypeBody);

        let mut nesting = Nesting::default();
        while !self.eof() {
            if self.at_kind(SyntaxKind::Newline)
                && nesting.is_root()
                && self.line_break_starts_new_top_level_item()
            {
                break;
            }

            let current = self.current_kind().expect("not eof");
            nesting = nesting.bump(current);
            self.bump();
        }

        self.finish_node();
    }

    fn parse_line_tail(&mut self) {
        loop {
            match self.current_kind() {
                Some(SyntaxKind::Whitespace) => self.bump(),
                Some(SyntaxKind::Comment | SyntaxKind::DocComment) => {
                    self.bump();
                    break;
                },
                _ => break,
            }
        }
    }

    fn parse_begin_block(&mut self) {
        self.start_node(SyntaxKind::BeginBlock);
        self.expect_keyword("begin", "expected `begin`");
        self.parse_block(&["end"]);
        self.expect_keyword("end", "expected `end` to close `begin` block");
        self.finish_node();
    }

    fn parse_procedure(&mut self) {
        self.start_node(SyntaxKind::Procedure);

        loop {
            self.bump_regular_trivia();
            if !self.at_kind(SyntaxKind::At) {
                break;
            }
            self.parse_attribute();
        }

        self.bump_regular_trivia();
        if self.at_keyword("pub") {
            self.parse_visibility();
        }

        self.bump_regular_trivia();
        if !self.expect_keyword("proc", "expected `proc` in procedure declaration") {
            self.finish_node();
            return;
        }

        self.bump_regular_trivia();
        if self.at_name_like() {
            self.bump();
        } else {
            self.error_here("expected a procedure name");
        }

        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::LParen) {
            self.parse_signature();
        }

        self.parse_block(&["end"]);
        self.expect_keyword("end", "expected `end` to close procedure");
        self.finish_node();
    }

    fn parse_attribute(&mut self) {
        self.start_node(SyntaxKind::Attribute);
        let _ = self.expect_kind(SyntaxKind::At, "expected `@`");
        self.bump_regular_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected an attribute name");
        }

        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::LParen) {
            self.parse_balanced_group(
                SyntaxKind::LParen,
                SyntaxKind::RParen,
                "expected `)` to close attribute arguments",
            );
        }
        self.finish_node();
    }

    fn parse_visibility(&mut self) {
        self.start_node(SyntaxKind::Visibility);
        let _ = self.expect_keyword("pub", "expected `pub`");
        self.finish_node();
    }

    fn parse_signature(&mut self) {
        self.start_node(SyntaxKind::Signature);
        self.parse_balanced_group(
            SyntaxKind::LParen,
            SyntaxKind::RParen,
            "expected `)` to close procedure parameters",
        );

        self.bump_regular_trivia();
        if self.at_kind(SyntaxKind::RArrow) {
            self.bump();
            self.bump_regular_trivia();
            if self.at_kind(SyntaxKind::LParen) {
                self.parse_balanced_group(
                    SyntaxKind::LParen,
                    SyntaxKind::RParen,
                    "expected `)` to close procedure results",
                );
            } else {
                self.parse_signature_result_until_line_end();
            }
        }
        self.finish_node();
    }

    fn parse_signature_result_until_line_end(&mut self) {
        let start = self.pos;
        let mut nesting = Nesting::default();
        while !self.eof() {
            let kind = self.current_kind().expect("not eof");
            if nesting.is_root() && matches!(kind, SyntaxKind::Comment | SyntaxKind::DocComment) {
                break;
            }
            if nesting.is_root() && kind == SyntaxKind::Newline {
                break;
            }

            nesting = nesting.bump(kind);
            self.bump();
        }

        if self.pos == start {
            self.error_here("expected a result type after `->` in procedure signature");
        }
    }

    fn parse_block(&mut self, terminators: &[&str]) {
        self.start_node(SyntaxKind::Block);
        while !self.eof() {
            if self.at_terminator(terminators) {
                break;
            }

            if self.at_kind(SyntaxKind::DocComment) || self.at_regular_trivia() {
                self.bump();
                continue;
            }

            if self.at_keyword("if") {
                self.parse_if();
            } else if self.at_keyword("while") {
                self.parse_while();
            } else if self.at_keyword("repeat") {
                self.parse_repeat();
            } else if self.can_start_instruction() {
                self.parse_instruction();
            } else {
                self.start_node(SyntaxKind::Error);
                self.error_here("unexpected token in block");
                self.bump();
                self.finish_node();
            }
        }
        self.finish_node();
    }

    fn parse_if(&mut self) {
        self.start_node(SyntaxKind::IfOp);
        self.expect_keyword("if", "expected `if`");
        self.parse_structured_header_suffixes();
        self.parse_block(&["else", "end"]);
        if self.at_keyword("else") {
            self.bump();
            self.parse_block(&["end"]);
        }
        self.expect_keyword("end", "expected `end` to close `if`");
        self.finish_node();
    }

    fn parse_while(&mut self) {
        self.start_node(SyntaxKind::WhileOp);
        self.expect_keyword("while", "expected `while`");
        self.parse_structured_header_suffixes();
        self.parse_block(&["end"]);
        self.expect_keyword("end", "expected `end` to close `while`");
        self.finish_node();
    }

    fn parse_repeat(&mut self) {
        self.start_node(SyntaxKind::RepeatOp);
        self.expect_keyword("repeat", "expected `repeat`");
        self.parse_structured_header_suffixes();
        self.parse_block(&["end"]);
        self.expect_keyword("end", "expected `end` to close `repeat`");
        self.finish_node();
    }

    fn parse_structured_header_suffixes(&mut self) {
        loop {
            self.bump_inline_whitespace();
            if !self.at_kind(SyntaxKind::Dot) {
                break;
            }
            self.bump();
            self.bump_inline_whitespace();

            if self.at_kind(SyntaxKind::LBracket) {
                self.parse_balanced_group(
                    SyntaxKind::LBracket,
                    SyntaxKind::RBracket,
                    "expected `]` to close structured operation suffix",
                );
            } else if self.at_name_like()
                || self.at_keyword_like()
                || self.at_kind(SyntaxKind::Number)
                || self.at_kind(SyntaxKind::QuotedString)
            {
                self.bump();
            } else {
                self.error_here("expected a structured operation suffix");
                break;
            }
        }
    }

    fn parse_instruction(&mut self) {
        self.start_node(SyntaxKind::Instruction);

        let mut nesting = Nesting::default();
        let mut previous_significant = None;
        while !self.eof() {
            let kind = self.current_kind().expect("not eof");
            if kind == SyntaxKind::Whitespace {
                if self.should_continue_instruction_after_whitespace(previous_significant, nesting)
                {
                    self.bump();
                    continue;
                }
                break;
            }

            if matches!(kind, SyntaxKind::Newline | SyntaxKind::Comment | SyntaxKind::DocComment) {
                if nesting.is_root() {
                    break;
                }
                self.bump();
                continue;
            }

            if previous_significant.is_some()
                && self.should_stop_instruction_before(kind, previous_significant, nesting)
            {
                break;
            }

            previous_significant = Some(kind);
            nesting = nesting.bump(kind);
            self.bump();
        }

        self.finish_node();
    }

    fn parse_balanced_group(
        &mut self,
        open: SyntaxKind,
        close: SyntaxKind,
        missing_message: &'static str,
    ) {
        self.bump_regular_trivia();
        if !self.expect_kind(open, missing_message) {
            return;
        }

        let mut depth = 1usize;
        while !self.eof() {
            let kind = self.current_kind().expect("not eof");
            if kind == open {
                depth += 1;
            } else if kind == close {
                depth -= 1;
            }
            self.bump();
            if depth == 0 {
                return;
            }
        }

        self.error_at_eof(missing_message);
    }

    fn should_continue_instruction_after_whitespace(
        &self,
        previous_significant: Option<SyntaxKind>,
        nesting: Nesting,
    ) -> bool {
        if !nesting.is_root() {
            return true;
        }

        let Some(previous_significant) = previous_significant else {
            return false;
        };
        if expects_continuation_operand(previous_significant) {
            return true;
        }

        matches!(
            self.peek_after_inline_whitespace(),
            Some(
                SyntaxKind::Dot
                    | SyntaxKind::Equal
                    | SyntaxKind::Comma
                    | SyntaxKind::DotDot
                    | SyntaxKind::Colon
                    | SyntaxKind::ColonColon
                    | SyntaxKind::RArrow
                    | SyntaxKind::Plus
                    | SyntaxKind::Minus
                    | SyntaxKind::Star
                    | SyntaxKind::Slash
                    | SyntaxKind::SlashSlash
                    | SyntaxKind::RBracket
                    | SyntaxKind::RParen
                    | SyntaxKind::RBrace
            )
        )
    }

    fn should_stop_instruction_before(
        &self,
        current: SyntaxKind,
        previous_significant: Option<SyntaxKind>,
        nesting: Nesting,
    ) -> bool {
        if !nesting.is_root() {
            return false;
        }

        if let Some(previous_significant) = previous_significant {
            if expects_continuation_operand(previous_significant) {
                return false;
            }
        }

        if punctuation_continues_instruction(current) {
            return false;
        }

        self.at_terminator(&["else", "end"]) || self.can_start_operation()
    }

    fn line_break_starts_new_top_level_item(&self) -> bool {
        match self.next_relevant_top_level_token(self.pos + 1) {
            Some(index) => self.is_top_level_starter(index),
            None => true,
        }
    }

    fn next_relevant_top_level_token(&self, mut index: usize) -> Option<usize> {
        while let Some(token) = self.tokens.get(index) {
            match token.kind() {
                SyntaxKind::Whitespace | SyntaxKind::Newline | SyntaxKind::Comment => index += 1,
                _ => return Some(index),
            }
        }
        None
    }

    fn peek_after_inline_whitespace(&self) -> Option<SyntaxKind> {
        let mut index = self.pos;
        while let Some(token) = self.tokens.get(index) {
            match token.kind() {
                SyntaxKind::Whitespace => index += 1,
                SyntaxKind::Newline | SyntaxKind::Comment | SyntaxKind::DocComment => return None,
                kind => return Some(kind),
            }
        }
        None
    }

    fn is_top_level_starter(&self, index: usize) -> bool {
        let Some(token) = self.tokens.get(index) else {
            return false;
        };

        token.kind() == SyntaxKind::DocComment
            || token.kind() == SyntaxKind::At
            || (token.kind() == SyntaxKind::Ident
                && matches!(
                    token.text(),
                    "adv_map" | "begin" | "const" | "enum" | "proc" | "pub" | "type" | "use"
                ))
    }

    fn can_start_operation(&self) -> bool {
        self.can_start_instruction()
            || self.at_keyword("if")
            || self.at_keyword("while")
            || self.at_keyword("repeat")
    }

    fn can_start_instruction(&self) -> bool {
        self.at_name_like() || self.at_keyword_like()
    }

    fn at_terminator(&self, terminators: &[&str]) -> bool {
        terminators.iter().any(|terminator| self.at_keyword(terminator))
    }

    fn at_name_like(&self) -> bool {
        matches!(
            self.current_kind(),
            Some(SyntaxKind::Ident | SyntaxKind::SpecialIdent | SyntaxKind::QuotedIdent)
        )
    }

    fn at_keyword_like(&self) -> bool {
        self.current_kind() == Some(SyntaxKind::Ident)
    }

    fn at_keyword(&self, keyword: &str) -> bool {
        matches!(self.current(), Some(token) if token.kind() == SyntaxKind::Ident && token.text() == keyword)
    }

    fn at_prefixed_keyword(&self, prefix: &str, keyword: &str) -> bool {
        if !self.at_keyword(prefix) {
            return false;
        }

        matches!(
            self.next_relevant_top_level_token(self.pos + 1).and_then(|index| self.tokens.get(index)),
            Some(token) if token.kind() == SyntaxKind::Ident && token.text() == keyword
        )
    }

    fn at_regular_trivia(&self) -> bool {
        matches!(
            self.current_kind(),
            Some(SyntaxKind::Whitespace | SyntaxKind::Newline | SyntaxKind::Comment)
        )
    }

    fn at_kind(&self, kind: SyntaxKind) -> bool {
        self.current_kind() == Some(kind)
    }

    fn current(&self) -> Option<&Token<'input>> {
        self.tokens.get(self.pos)
    }

    fn current_kind(&self) -> Option<SyntaxKind> {
        self.current().map(Token::kind)
    }

    fn eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn bump_regular_trivia(&mut self) {
        while self.at_regular_trivia() {
            self.bump();
        }
    }

    fn bump_inline_whitespace(&mut self) {
        while self.at_kind(SyntaxKind::Whitespace) {
            self.bump();
        }
    }

    fn expect_keyword(&mut self, keyword: &str, message: &'static str) -> bool {
        self.bump_regular_trivia();
        if self.at_keyword(keyword) {
            self.bump();
            true
        } else {
            self.error_here(message);
            false
        }
    }

    fn expect_kind(&mut self, kind: SyntaxKind, message: &'static str) -> bool {
        self.bump_regular_trivia();
        if self.at_kind(kind) {
            self.bump();
            true
        } else {
            self.error_here(message);
            false
        }
    }

    fn start_node(&mut self, kind: SyntaxKind) {
        self.builder.start_node(kind.into());
    }

    fn finish_node(&mut self) {
        self.builder.finish_node();
    }

    fn bump(&mut self) {
        if let Some(token) = self.current() {
            let kind = token.kind();
            let span = token.span();
            let text = token.text();
            if kind == SyntaxKind::Error {
                self.diagnostics
                    .push(Diagnostic::new(span, format!("unrecognized token `{text}`")));
            }
            self.builder.token(kind.into(), text);
            self.pos += 1;
        }
    }

    fn error_here(&mut self, message: impl Into<String>) {
        let span = self
            .current()
            .map(|token| token.span())
            .unwrap_or(self.input_len..self.input_len);
        self.diagnostics.push(Diagnostic::new(span, message));
    }

    fn error_at_eof(&mut self, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::new(self.input_len..self.input_len, message));
    }
}

fn expects_continuation_operand(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Dot
            | SyntaxKind::Equal
            | SyntaxKind::Comma
            | SyntaxKind::DotDot
            | SyntaxKind::Colon
            | SyntaxKind::ColonColon
            | SyntaxKind::RArrow
            | SyntaxKind::Plus
            | SyntaxKind::Minus
            | SyntaxKind::Star
            | SyntaxKind::Slash
            | SyntaxKind::SlashSlash
            | SyntaxKind::LBracket
            | SyntaxKind::LParen
            | SyntaxKind::LBrace
    )
}

fn punctuation_continues_instruction(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Dot
            | SyntaxKind::Equal
            | SyntaxKind::Comma
            | SyntaxKind::DotDot
            | SyntaxKind::Colon
            | SyntaxKind::ColonColon
            | SyntaxKind::RArrow
            | SyntaxKind::Plus
            | SyntaxKind::Minus
            | SyntaxKind::Star
            | SyntaxKind::Slash
            | SyntaxKind::SlashSlash
            | SyntaxKind::RBracket
            | SyntaxKind::RParen
            | SyntaxKind::RBrace
    )
}

#[cfg(test)]
mod tests {
    use rowan::ast::AstNode;

    use crate::{
        ast::{Item, SourceFile},
        parse_text,
        syntax::SyntaxKind,
    };

    #[test]
    fn parses_top_level_forms_and_nested_structured_ops() {
        let source = "\
#! docs
pub use foo::bar -> baz
pub const X = 1
pub type FeltAlias = felt
adv_map TABLE = [0x01, 0x02]
begin
    if.true
        repeat.4
            swap dup.1 add
        end
    else
        while.true
            nop
        end
    end
end
pub proc foo(a) -> (b)
    exec.bar
end
";
        let parse = parse_text(source);
        assert!(!parse.has_errors());
        let root = parse.syntax();
        assert_eq!(root.kind(), SyntaxKind::SourceFile);

        let child_kinds = root.children().map(|child| child.kind()).collect::<Vec<_>>();
        assert_eq!(
            child_kinds,
            vec![
                SyntaxKind::ModuleDoc,
                SyntaxKind::Import,
                SyntaxKind::Constant,
                SyntaxKind::TypeDecl,
                SyntaxKind::AdviceMap,
                SyntaxKind::BeginBlock,
                SyntaxKind::Procedure,
            ]
        );

        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::IfOp));
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::RepeatOp));
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::WhileOp));
    }

    #[test]
    fn exposes_typed_wrappers_for_structured_top_level_forms() {
        let source = "\
pub use miden::core::mem -> memory
pub const EVENT = event(\"miden::event\")
pub enum Bool : u8 {
    FALSE,
    TRUE = 1,
}
adv_map TABLE(0x0200000000000000020000000000000002000000000000000200000000000000) = [0x01, 0x02]
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let source_file = SourceFile::cast(parse.syntax()).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 4);

        let Item::Import(import) = &items[0] else {
            panic!("expected import, got {:?}", items[0]);
        };
        assert_eq!(
            import
                .path()
                .expect("import path")
                .segments()
                .map(|segment| segment.text().to_string())
                .collect::<Vec<_>>(),
            vec!["miden", "core", "mem"]
        );
        assert_eq!(import.alias_token().expect("alias").text(), "memory");

        let Item::Constant(constant) = &items[1] else {
            panic!("expected constant, got {:?}", items[1]);
        };
        assert_eq!(constant.name_token().expect("constant name").text(), "EVENT");
        assert_eq!(
            constant
                .expr()
                .expect("constant expr")
                .significant_tokens()
                .map(|token| token.text().to_string())
                .collect::<Vec<_>>(),
            vec!["event", "(", "\"miden::event\"", ")"]
        );

        let Item::TypeDecl(type_decl) = &items[2] else {
            panic!("expected type declaration, got {:?}", items[2]);
        };
        assert_eq!(type_decl.keyword_token().expect("type keyword").text(), "enum");
        assert_eq!(type_decl.name_token().expect("type name").text(), "Bool");
        assert!(
            type_decl.body().is_some(),
            "expected enum declaration to expose a structured type body"
        );

        let Item::AdviceMap(advice_map) = &items[3] else {
            panic!("expected advice map, got {:?}", items[3]);
        };
        assert_eq!(advice_map.name_token().expect("advice map name").text(), "TABLE");
        assert_eq!(
            advice_map
                .value_expr()
                .expect("advice map value")
                .significant_tokens()
                .map(|token| token.text().to_string())
                .collect::<Vec<_>>(),
            vec!["[", "0x01", ",", "0x02", "]"]
        );
    }

    #[test]
    fn parses_unparenthesized_procedure_result_types() {
        let source = "\
pub proc println(message: ptr<u8, addrspace(byte)>) -> ptr<u8, addrspace(byte)>
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let root = parse.syntax();
        let source_file = SourceFile::cast(root).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);

        let Item::Procedure(procedure) = &items[0] else {
            panic!("expected procedure, got {:?}", items[0]);
        };
        assert!(
            procedure.signature().is_some(),
            "expected procedure to retain its signature node"
        );
    }

    #[test]
    fn parses_multiline_import_aliases() {
        let source = "\
pub use ::miden::core::collections::sorted_array::lowerbound_key_value
    -> lowerbound_key_value
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let source_file = SourceFile::cast(parse.syntax()).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);

        let Item::Import(import) = &items[0] else {
            panic!("expected import, got {:?}", items[0]);
        };
        assert_eq!(import.alias_token().expect("alias").text(), "lowerbound_key_value");
    }

    #[test]
    fn recovers_from_missing_end_tokens() {
        let parse = parse_text("begin\n    if.true\n        add\n");
        assert!(parse.has_errors());
        assert!(
            parse.diagnostics().iter().any(|diag| diag.message().contains("expected `end`")),
            "expected an `end`-related diagnostic, got {:?}",
            parse.diagnostics()
        );

        let root = parse.syntax();
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::BeginBlock));
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::IfOp));
    }

    #[test]
    fn surfaces_invalid_tokens_as_diagnostics() {
        let parse = parse_text("proc foo\n    §\nend\n");
        assert!(parse.has_errors());
        assert!(parse.diagnostics().iter().any(|diag| diag.message().contains("unrecognized")));
    }
}
