use std::sync::Arc;

use miden_debug_types::{SourceFile, SourceId, SourceLanguage, SourceSpan, Uri};
use rowan::{GreenNodeBuilder, NodeOrToken, TextRange};

use crate::{
    ast::AstNode,
    diagnostics::{LabeledSpan, Severity, diagnostic, miette::MietteDiagnostic as Diagnostic},
    lexer::{Token, tokenize},
    syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken},
};

/// The result of parsing a MASM source file into a lossless CST.
///
/// This type owns the green tree, retains the originating [`SourceFile`], and exposes both
/// diagnostics and span helpers for later lowering.
#[derive(Debug, Clone)]
pub struct Parse {
    source: Arc<SourceFile>,
    green_node: rowan::GreenNode,
    diagnostics: Vec<Diagnostic>,
}

impl Parse {
    /// Returns the raw rowan syntax tree rooted at [`SyntaxKind::SourceFile`].
    pub fn syntax(&self) -> SyntaxNode {
        SyntaxNode::new_root(self.green_node.clone())
    }

    /// Returns the typed root node for this parse.
    pub fn root(&self) -> crate::ast::SourceFile {
        crate::ast::SourceFile::cast(self.syntax())
            .expect("parse root kind should always be SourceFile")
    }

    /// Returns any syntax diagnostics emitted while building the CST.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Removes and returns any syntax diagnostics emitted while building the CST.
    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        core::mem::take(&mut self.diagnostics)
    }

    /// Returns the source file used to produce this parse result.
    pub fn source_file(&self) -> Arc<SourceFile> {
        Arc::clone(&self.source)
    }

    /// Returns the source file used to produce this parse result by shared reference.
    pub fn source(&self) -> &SourceFile {
        self.source.as_ref()
    }

    /// Returns `true` when the parse emitted at least one syntax diagnostic.
    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }

    /// Maps a rowan node back to a [`SourceSpan`] in the originating source file.
    pub fn span_for_node(&self, node: &SyntaxNode) -> SourceSpan {
        self.span_for_range(node.text_range())
    }

    /// Maps a rowan token back to a [`SourceSpan`] in the originating source file.
    pub fn span_for_token(&self, token: &SyntaxToken) -> SourceSpan {
        self.span_for_range(token.text_range())
    }

    /// Maps a rowan element back to a [`SourceSpan`] in the originating source file.
    pub fn span_for_element(&self, element: &SyntaxElement) -> SourceSpan {
        match element {
            NodeOrToken::Node(node) => self.span_for_node(node),
            NodeOrToken::Token(token) => self.span_for_token(token),
        }
    }

    /// Converts a rowan [`TextRange`] to a [`SourceSpan`] in the originating source file.
    pub fn span_for_range(&self, range: TextRange) -> SourceSpan {
        source_span_from_text_range(self.source.id(), range)
    }
}

/// Parses a source-managed MASM file into a lossless CST.
pub fn parse_source_file(source: Arc<SourceFile>) -> Parse {
    let parser_source = Arc::clone(&source);
    Parser::new(parser_source.as_ref()).parse(source)
}

/// Parses raw MASM text into a detached CST with [`SourceId::UNKNOWN`] spans.
///
/// This is primarily intended for tests and ad hoc helpers. Production callers should prefer
/// [`parse_source_file`] so diagnostics and spans remain attached to a real [`SourceFile`].
pub fn parse_text(input: &str) -> Parse {
    parse_source_file(detached_source_file(input))
}

struct Parser<'input> {
    tokens: Vec<Token<'input>>,
    pos: usize,
    builder: GreenNodeBuilder<'static>,
    diagnostics: Vec<Diagnostic>,
    eof_span: SourceSpan,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockOwner {
    Begin,
    Procedure,
    If,
    While,
    Repeat,
}

impl BlockOwner {
    fn missing_end_message(self) -> &'static str {
        match self {
            Self::Begin => "expected `end` to close `begin` block",
            Self::Procedure => "expected `end` to close procedure",
            Self::If => "expected `end` to close `if`",
            Self::While => "expected `end` to close `while`",
            Self::Repeat => "expected `end` to close `repeat`",
        }
    }

    fn recovery_message(self, boundary: BlockRecoveryBoundary) -> String {
        match boundary {
            BlockRecoveryBoundary::Else => {
                format!("{} before `else`", self.missing_end_message())
            },
            BlockRecoveryBoundary::TopLevelItem => {
                format!("{} before top-level item", self.missing_end_message())
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockRecoveryBoundary {
    Else,
    TopLevelItem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockParseOutcome {
    FoundTerminator,
    RecoveredImplicitEnd,
    ReachedEof,
}

impl<'input> Parser<'input> {
    fn new(source: &'input SourceFile) -> Self {
        let eof_span = eof_anchor_span(source);
        Self {
            tokens: tokenize(source),
            pos: 0,
            builder: GreenNodeBuilder::new(),
            diagnostics: Vec::new(),
            eof_span,
        }
    }

    fn parse(mut self, source: Arc<SourceFile>) -> Parse {
        self.start_node(SyntaxKind::SourceFile);
        while !self.eof() {
            self.parse_source_item();
        }
        self.finish_node();

        Parse {
            source,
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
            self.parse_procedure();
            return;
        }

        if self.at_keyword("begin") {
            self.parse_begin_block();
            return;
        }

        if self.at_keyword("use") || self.at_prefixed_keyword("pub", "use") {
            self.parse_import();
            return;
        }

        if self.at_keyword("const") || self.at_prefixed_keyword("pub", "const") {
            self.parse_constant();
            return;
        }

        if self.at_keyword("type")
            || self.at_keyword("enum")
            || self.at_prefixed_keyword("pub", "type")
            || self.at_prefixed_keyword("pub", "enum")
        {
            self.parse_type_decl();
            return;
        }

        if self.at_keyword("adv_map") {
            self.parse_advice_map();
            return;
        }

        self.start_node(SyntaxKind::Error);
        self.error_here("unexpected top-level token");
        self.bump();
        self.finish_node();
    }

    fn parse_doc_form(&mut self) {
        self.start_node(SyntaxKind::Doc);
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

        if self.peek_after_non_comment_trivia() == Some(SyntaxKind::RArrow) {
            self.bump_non_comment_trivia();
            self.bump();
            self.bump_non_comment_trivia();
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

        self.bump_non_comment_trivia();
        if self.at_name_like() || self.at_keyword_like() {
            self.bump();
        } else {
            self.error_here("expected an import path");
            self.finish_node();
            return;
        }

        loop {
            if self.peek_after_non_comment_trivia() != Some(SyntaxKind::ColonColon) {
                break;
            }

            self.bump_non_comment_trivia();
            self.bump();
            self.bump_non_comment_trivia();
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
        let mut saw_significant = false;
        while !self.eof() {
            let kind = self.current_kind().expect("not eof");
            if nesting.is_root() && matches!(kind, SyntaxKind::Comment | SyntaxKind::DocComment) {
                break;
            }
            if nesting.is_root() && kind == SyntaxKind::Newline {
                break;
            }
            if nesting.is_root()
                && saw_significant
                && kind == SyntaxKind::Whitespace
                && self
                    .next_relevant_top_level_token(self.pos + 1)
                    .is_some_and(|index| self.is_top_level_starter(index))
            {
                break;
            }

            saw_significant |= !kind.is_trivia();
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
                Some(SyntaxKind::Comment) => {
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
        self.parse_line_tail();
        if self.parse_block(BlockOwner::Begin, &["end"]) == BlockParseOutcome::FoundTerminator {
            self.expect_keyword("end", BlockOwner::Begin.missing_end_message());
        }
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

        self.parse_line_tail();
        if self.parse_block(BlockOwner::Procedure, &["end"]) == BlockParseOutcome::FoundTerminator {
            self.expect_keyword("end", BlockOwner::Procedure.missing_end_message());
        }
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

        self.bump_non_comment_trivia();
        if self.at_kind(SyntaxKind::RArrow) {
            self.bump();
            self.bump_non_comment_trivia();
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

    fn parse_block(&mut self, owner: BlockOwner, terminators: &[&str]) -> BlockParseOutcome {
        self.start_node(SyntaxKind::Block);
        while !self.eof() {
            if self.at_terminator(terminators) {
                self.finish_node();
                return BlockParseOutcome::FoundTerminator;
            }

            if self.doc_comment_looks_like_regular_comment_in_block() {
                self.bump();
                continue;
            }

            if self.at_regular_trivia() {
                self.bump();
                continue;
            }

            if let Some(boundary) = self.block_recovery_boundary(terminators) {
                self.start_node(SyntaxKind::Error);
                self.error_here(owner.recovery_message(boundary));
                self.finish_node();
                self.finish_node();
                return BlockParseOutcome::RecoveredImplicitEnd;
            }

            if self.at_keyword("if") {
                if self.parse_if() {
                    self.finish_node();
                    return BlockParseOutcome::ReachedEof;
                }
            } else if self.at_keyword("while") {
                if self.parse_while() {
                    self.finish_node();
                    return BlockParseOutcome::ReachedEof;
                }
            } else if self.at_keyword("repeat") {
                if self.parse_repeat() {
                    self.finish_node();
                    return BlockParseOutcome::ReachedEof;
                }
            } else if self.can_start_instruction() {
                self.parse_instruction();
            } else {
                self.start_node(SyntaxKind::Error);
                self.error_here("unexpected token in block");
                self.bump();
                self.finish_node();
            }
        }

        self.error_at_eof(owner.missing_end_message());
        self.finish_node();
        BlockParseOutcome::ReachedEof
    }

    fn parse_if(&mut self) -> bool {
        self.start_node(SyntaxKind::IfOp);
        self.expect_keyword("if", "expected `if`");
        self.parse_structured_header_suffixes();
        self.parse_line_tail();
        let then_outcome = self.parse_block(BlockOwner::If, &["else", "end"]);
        if then_outcome == BlockParseOutcome::ReachedEof {
            self.finish_node();
            return true;
        }
        let mut needs_end = then_outcome == BlockParseOutcome::FoundTerminator;
        if self.at_keyword("else") {
            self.bump();
            self.parse_line_tail();
            let else_outcome = self.parse_block(BlockOwner::If, &["end"]);
            if else_outcome == BlockParseOutcome::ReachedEof {
                self.finish_node();
                return true;
            }
            needs_end = else_outcome == BlockParseOutcome::FoundTerminator;
        }
        if needs_end {
            self.expect_keyword("end", BlockOwner::If.missing_end_message());
        }
        self.finish_node();
        false
    }

    fn parse_while(&mut self) -> bool {
        self.start_node(SyntaxKind::WhileOp);
        self.expect_keyword("while", "expected `while`");
        self.parse_structured_header_suffixes();
        self.parse_line_tail();
        let outcome = self.parse_block(BlockOwner::While, &["end"]);
        if outcome == BlockParseOutcome::ReachedEof {
            self.finish_node();
            return true;
        }
        if outcome == BlockParseOutcome::FoundTerminator {
            self.expect_keyword("end", BlockOwner::While.missing_end_message());
        }
        self.finish_node();
        false
    }

    fn parse_repeat(&mut self) -> bool {
        self.start_node(SyntaxKind::RepeatOp);
        self.expect_keyword("repeat", "expected `repeat`");
        self.parse_structured_header_suffixes();
        self.parse_line_tail();
        let outcome = self.parse_block(BlockOwner::Repeat, &["end"]);
        if outcome == BlockParseOutcome::ReachedEof {
            self.finish_node();
            return true;
        }
        if outcome == BlockParseOutcome::FoundTerminator {
            self.expect_keyword("end", BlockOwner::Repeat.missing_end_message());
        }
        self.finish_node();
        false
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

        if let Some(previous_significant) = previous_significant
            && expects_continuation_operand(previous_significant)
        {
            return false;
        }

        if punctuation_continues_instruction(current) {
            return false;
        }

        self.at_terminator(&["else", "end"])
            || self.can_start_operation()
            || self.at_block_recovery_boundary()
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

    fn next_relevant_block_token(&self, mut index: usize) -> Option<usize> {
        while let Some(token) = self.tokens.get(index) {
            match token.kind() {
                SyntaxKind::Whitespace
                | SyntaxKind::Newline
                | SyntaxKind::Comment
                | SyntaxKind::DocComment => index += 1,
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

    fn peek_after_non_comment_trivia(&self) -> Option<SyntaxKind> {
        let mut index = self.pos;
        while let Some(token) = self.tokens.get(index) {
            match token.kind() {
                SyntaxKind::Whitespace | SyntaxKind::Newline => index += 1,
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
                && match token.text() {
                    "adv_map" | "begin" | "const" | "enum" | "proc" | "type" | "use" => true,
                    "pub" => matches!(
                        self.next_relevant_top_level_token(index + 1)
                            .and_then(|next| self.tokens.get(next)),
                        Some(next)
                            if next.kind() == SyntaxKind::Ident
                                && matches!(next.text(), "const" | "enum" | "proc" | "type" | "use")
                    ),
                    _ => false,
                })
    }

    fn can_start_operation(&self) -> bool {
        self.can_start_instruction()
            || self.at_keyword("if")
            || self.at_keyword("while")
            || self.at_keyword("repeat")
    }

    fn can_start_instruction(&self) -> bool {
        matches!(
            self.current(),
            Some(token)
                if matches!(
                    token.kind(),
                    SyntaxKind::Ident | SyntaxKind::SpecialIdent | SyntaxKind::QuotedIdent
                ) && (token.kind() != SyntaxKind::Ident
                    || !is_reserved_block_keyword(token.text()))
        )
    }

    fn block_recovery_boundary(&self, terminators: &[&str]) -> Option<BlockRecoveryBoundary> {
        if self.at_keyword("else") && !terminators.contains(&"else") {
            return Some(BlockRecoveryBoundary::Else);
        }

        if self.at_top_level_form_starter_in_block() {
            return Some(BlockRecoveryBoundary::TopLevelItem);
        }

        None
    }

    fn at_block_recovery_boundary(&self) -> bool {
        self.at_keyword("else") || self.at_top_level_form_starter_in_block()
    }

    fn at_top_level_form_starter(&self) -> bool {
        self.is_top_level_starter(self.pos)
    }

    fn at_top_level_form_starter_in_block(&self) -> bool {
        match self.current() {
            Some(token) if token.kind() == SyntaxKind::DocComment => self
                .next_relevant_block_token(self.pos + 1)
                .is_some_and(|index| self.is_top_level_starter(index)),
            _ => self.at_top_level_form_starter(),
        }
    }

    fn doc_comment_looks_like_regular_comment_in_block(&self) -> bool {
        if !self.at_kind(SyntaxKind::DocComment) {
            return false;
        }

        self.next_relevant_block_token(self.pos + 1)
            .and_then(|index| self.tokens.get(index).map(|token| (index, token)))
            .is_some_and(|(index, token)| {
                token.kind() == SyntaxKind::Ident
                    && !self.is_top_level_starter(index)
                    && is_non_top_level_block_keyword(token.text())
            })
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

    fn bump_non_comment_trivia(&mut self) {
        while matches!(self.current_kind(), Some(SyntaxKind::Whitespace | SyntaxKind::Newline)) {
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
                self.diagnostics.push(diagnostic!(
                    severity = Severity::Error,
                    labels = vec![LabeledSpan::at(span, format!("unrecognized token `{text}`"))],
                    "syntax error"
                ));
            }
            self.builder.token(kind.into(), text);
            self.pos += 1;
        }
    }

    fn error_here(&mut self, message: impl Into<String>) {
        let span = self.current().map(|token| token.span()).unwrap_or(self.eof_span);
        self.diagnostics.push(diagnostic!(
            severity = Severity::Error,
            labels = vec![LabeledSpan::at(span, message.into())],
            "syntax error"
        ));
    }

    fn error_at_eof(&mut self, message: impl Into<String>) {
        self.diagnostics.push(diagnostic!(
            severity = Severity::Error,
            labels = vec![LabeledSpan::at(self.eof_span, message.into())],
            "syntax error"
        ));
    }
}

fn detached_source_file(input: &str) -> Arc<SourceFile> {
    Arc::new(SourceFile::new(
        SourceId::UNKNOWN,
        SourceLanguage::Masm,
        Uri::new("memory:///inline.masm"),
        input.to_owned().into_boxed_str(),
    ))
}

fn eof_anchor_span(source: &SourceFile) -> SourceSpan {
    source
        .as_str()
        .char_indices()
        .last()
        .map(|(offset, _)| {
            SourceSpan::at(
                source.id(),
                u32::try_from(offset).expect("source files larger than 4GiB are not supported"),
            )
        })
        .unwrap_or_else(|| {
            SourceSpan::try_from_range(source.id(), 0..0)
                .expect("source files larger than 4GiB are not supported")
        })
}

fn source_span_from_text_range(source_id: SourceId, range: TextRange) -> SourceSpan {
    SourceSpan::new(source_id, u32::from(range.start())..u32::from(range.end()))
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

fn is_reserved_block_keyword(text: &str) -> bool {
    matches!(
        text,
        "adv_map"
            | "begin"
            | "const"
            | "else"
            | "end"
            | "enum"
            | "if"
            | "proc"
            | "pub"
            | "repeat"
            | "type"
            | "use"
            | "while"
    )
}

fn is_non_top_level_block_keyword(text: &str) -> bool {
    matches!(text, "else" | "end" | "if" | "repeat" | "while")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_debug_types::{
        SourceFile as ManagedSourceFile, SourceId, SourceLanguage, SourceSpan, Uri,
    };
    use rowan::ast::AstNode;

    use crate::{
        ast::{Item, SourceFile as AstSourceFile},
        parse_source_file, parse_text,
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
                SyntaxKind::Doc,
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

        let source_file = AstSourceFile::cast(parse.syntax()).expect("source file");
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
        let source_file = AstSourceFile::cast(root).expect("source file");
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

        let source_file = AstSourceFile::cast(parse.syntax()).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);

        let Item::Import(import) = &items[0] else {
            panic!("expected import, got {:?}", items[0]);
        };
        assert_eq!(import.alias_token().expect("alias").text(), "lowerbound_key_value");
    }

    #[test]
    fn keeps_header_comments_on_structured_nodes() {
        let source = "\
use ::miden::utils::panic # import
pub proc long_name(arg: felt) # proc
    nop
end
begin # begin
    if.true # if
        nop
    else # else
        nop
    end
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let root = parse.syntax();
        let procedure = root
            .descendants()
            .find(|node| node.kind() == SyntaxKind::Procedure)
            .expect("procedure");
        assert!(
            procedure
                .children_with_tokens()
                .filter_map(|element| element.into_token())
                .any(|token| token.kind() == SyntaxKind::Comment && token.text().contains("proc"))
        );

        let if_node = root
            .descendants()
            .find(|node| node.kind() == SyntaxKind::IfOp)
            .expect("if node");
        let if_comments = if_node
            .children_with_tokens()
            .filter_map(|element| element.into_token())
            .filter(|token| token.kind() == SyntaxKind::Comment)
            .map(|token| token.text().to_string())
            .collect::<Vec<_>>();
        assert!(
            if_comments.iter().any(|comment| comment.contains("if")),
            "expected header comment on if node, got {if_comments:?}"
        );
        assert!(
            if_comments.iter().any(|comment| comment.contains("else")),
            "expected else comment on if node, got {if_comments:?}"
        );
    }

    #[test]
    fn treats_block_local_doc_comments_as_regular_comments_before_block_keywords() {
        let source = "\
proc foo
    #! mistaken doc comment before if
    if.true
        nop
        #! mistaken doc comment before else
    else
        #! mistaken doc comment before while
        while.true
            add
        end
    end
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let root = parse.syntax();
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::Procedure));
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::IfOp));
        assert!(
            root.descendants().filter(|node| node.kind() == SyntaxKind::Instruction).count() >= 2
        );
    }

    #[test]
    fn block_local_doc_comments_before_instructions_still_error() {
        let source = "\
proc foo
    #! malformed doc comment before instruction
    loc_load.0
end
";

        let parse = parse_text(source);
        assert!(parse.has_errors());
        assert!(
            parse
                .diagnostics()
                .iter()
                .flat_map(|diag| diag.labels.as_deref().unwrap_or(&[]).iter())
                .filter_map(|label| label.label())
                .any(|label| label.contains("unexpected token in block")),
            "expected block-local doc comments before instructions to remain invalid, got {:?}",
            parse.diagnostics()
        );
    }

    #[test]
    fn block_local_doc_comments_still_recover_before_true_top_level_items() {
        let source = "\
proc foo
    #! actual misplaced doc comment
    pub const X = 1
";

        let parse = parse_text(source);
        assert!(parse.has_errors());
        assert!(
            parse
                .diagnostics()
                .iter()
                .flat_map(|diag| diag.labels.as_deref().unwrap_or(&[]).iter())
                .filter_map(|label| label.label())
                .any(|label| label.contains("before top-level item")),
            "expected block recovery before a top-level item, got {:?}",
            parse.diagnostics()
        );

        let root = parse.syntax();
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::Doc));

        let source_file = AstSourceFile::cast(root).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(
            items.len(),
            3,
            "expected recovery to preserve the recovered doc comment and top-level constant"
        );
        assert!(matches!(items[0], Item::Procedure(_)));
        assert!(matches!(items[1], Item::Doc(_)));
        assert!(matches!(items[2], Item::Constant(_)));
    }

    #[test]
    fn recovers_from_missing_end_tokens() {
        let parse = parse_text("begin\n    if.true\n        add\n");
        assert!(parse.has_errors());
        let end_labels = parse
            .diagnostics()
            .iter()
            .flat_map(|diag| diag.labels.as_deref().unwrap_or(&[]).iter())
            .filter_map(|label| label.label())
            .filter(|label| label.contains("expected `end`"))
            .collect::<Vec<_>>();
        assert_eq!(
            end_labels.len(),
            1,
            "expected exactly one missing-`end` diagnostic, got {:?}",
            parse.diagnostics()
        );
        assert!(
            end_labels[0].contains("`if`"),
            "expected the innermost unterminated block to own the diagnostic, got {end_labels:?}"
        );

        let root = parse.syntax();
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::BeginBlock));
        assert!(root.descendants().any(|node| node.kind() == SyntaxKind::IfOp));
    }

    #[test]
    fn recovers_before_top_level_items_inside_blocks() {
        let source = "\
proc foo
    if.true
        add
pub const X = 1
";
        let parse = parse_text(source);
        assert!(parse.has_errors());
        assert!(
            parse
                .diagnostics()
                .iter()
                .flat_map(|diag| diag.labels.as_deref().unwrap_or(&[]).iter())
                .filter_map(|label| label.label())
                .any(|label| label.contains("before top-level item")),
            "expected block recovery before a top-level item, got {:?}",
            parse.diagnostics()
        );

        let source_file = AstSourceFile::cast(parse.syntax()).expect("source file");
        let items = source_file.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 2, "expected recovery to preserve the top-level constant");
        assert!(matches!(items[0], Item::Procedure(_)));
        assert!(matches!(items[1], Item::Constant(_)));
        assert!(parse.syntax().descendants().any(|node| node.kind() == SyntaxKind::Error));
    }

    #[test]
    fn else_synchronizes_unterminated_nested_blocks() {
        let source = "\
proc foo
    if.true
        while.true
            nop
    else
        nop
    end
end
";
        let parse = parse_text(source);
        assert!(parse.has_errors());
        assert!(
            parse
                .diagnostics()
                .iter()
                .flat_map(|diag| diag.labels.as_deref().unwrap_or(&[]).iter())
                .filter_map(|label| label.label())
                .any(|label| label.contains("close `while` before `else`")),
            "expected the nested `while` to recover before `else`, got {:?}",
            parse.diagnostics()
        );

        let if_node = parse
            .syntax()
            .descendants()
            .find(|node| node.kind() == SyntaxKind::IfOp)
            .expect("if node");
        assert_eq!(
            if_node.children().filter(|child| child.kind() == SyntaxKind::Block).count(),
            2,
            "expected `else` to remain attached to the enclosing `if` after recovery"
        );
    }

    #[test]
    fn surfaces_invalid_tokens_as_diagnostics() {
        let parse = parse_text("proc foo\n    §\nend\n");
        assert!(parse.has_errors());
        assert!(parse.diagnostics().iter().any(|diag| diag.labels.as_ref().is_some_and(
            |labels| {
                labels
                    .iter()
                    .any(|l| l.label().is_some_and(|label| label.contains("unrecognized token")))
            }
        )));
    }

    #[test]
    fn parse_source_file_tracks_source_aware_spans() {
        let source = Arc::new(ManagedSourceFile::new(
            SourceId::new(11),
            SourceLanguage::Masm,
            Uri::new("memory:///parser-span-test.masm"),
            "begin\n    nop\nend\n".to_string().into_boxed_str(),
        ));

        let parse = parse_source_file(source.clone());
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());
        assert_eq!(parse.source_file().id(), source.id());

        let nop = parse
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .find(|token| token.text() == "nop")
            .expect("nop token");
        let offset = source.as_str().find("nop").expect("nop offset");
        let expected = SourceSpan::try_from_range(source.id(), offset..offset + 3).unwrap();
        assert_eq!(parse.span_for_token(&nop), expected);
    }

    #[test]
    fn diagnostics_keep_source_ids_from_managed_source_files() {
        let source = Arc::new(ManagedSourceFile::new(
            SourceId::new(12),
            SourceLanguage::Masm,
            Uri::new("memory:///parser-diagnostic-span-test.masm"),
            "proc foo\n    §\nend\n".to_string().into_boxed_str(),
        ));

        let parse = parse_source_file(source.clone());
        assert!(parse.has_errors());

        let diagnostic = parse
            .diagnostics()
            .iter()
            .find(|diag| {
                diag.labels.as_ref().is_some_and(|labels| {
                    labels.iter().any(|l| {
                        l.label().is_some_and(|label| label.contains("unrecognized token"))
                    })
                })
            })
            .expect("invalid-token diagnostic");
        let offset = source.as_str().find('§').expect("invalid token offset");
        let expected =
            SourceSpan::try_from_range(source.id(), offset..offset + '§'.len_utf8()).unwrap();
        let label_span = diagnostic.labels.as_deref().unwrap()[0].inner();
        let actual = SourceSpan::new(
            source.id(),
            (label_span.offset() as u32)..((label_span.offset() + label_span.len()) as u32),
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn eof_diagnostics_anchor_to_the_last_character_offset() {
        let source = Arc::new(ManagedSourceFile::new(
            SourceId::new(13),
            SourceLanguage::Masm,
            Uri::new("memory:///parser-eof-span-test.masm"),
            "begin\n    if.true\n        add\n".to_string().into_boxed_str(),
        ));

        let parse = parse_source_file(source.clone());
        assert!(parse.has_errors());

        let diagnostic = parse
            .diagnostics()
            .iter()
            .find(|diag| {
                diag.labels
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|label| label.label())
                    .any(|label| label.contains("expected `end`"))
            })
            .expect("missing-end diagnostic");

        let last_char_offset = source
            .as_str()
            .char_indices()
            .last()
            .map(|(offset, _)| offset)
            .expect("source should be non-empty");
        let label_span = diagnostic.labels.as_deref().unwrap()[0].inner();
        assert_eq!(label_span.offset(), last_char_offset);
        assert_eq!(label_span.len(), 0);
    }

    #[test]
    fn import_path_spans_do_not_consume_trailing_newlines() {
        let source = "use lib::a::FOO\nbegin end\n";
        let parse = parse_text(source);
        let source_file = AstSourceFile::cast(parse.syntax()).expect("source file");
        let Item::Import(import) = source_file.items().next().expect("import item") else {
            panic!("expected first item to be an import");
        };
        let path = import.path().expect("import path");
        let start = source.find("lib::a::FOO").expect("path start") as u32;
        let end = start + "lib::a::FOO".len() as u32;
        let expected = SourceSpan::new(parse.source().id(), start..end);
        assert_eq!(parse.span_for_node(path.syntax()), expected);
    }
}
