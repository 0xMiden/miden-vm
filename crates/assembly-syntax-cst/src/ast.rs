use rowan::ast::{AstNode, support};

use crate::syntax::{MasmLanguage, SyntaxKind, SyntaxNode, SyntaxToken};

macro_rules! ast_node {
    ($name:ident, $kind:path) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            syntax: SyntaxNode,
        }

        impl AstNode for $name {
            type Language = MasmLanguage;

            fn can_cast(kind: SyntaxKind) -> bool {
                kind == $kind
            }

            fn cast(syntax: SyntaxNode) -> Option<Self> {
                Self::can_cast(syntax.kind()).then_some(Self { syntax })
            }

            fn syntax(&self) -> &SyntaxNode {
                &self.syntax
            }
        }
    };
}

ast_node!(SourceFile, SyntaxKind::SourceFile);
ast_node!(ModuleDoc, SyntaxKind::ModuleDoc);
ast_node!(Doc, SyntaxKind::Doc);
ast_node!(Import, SyntaxKind::Import);
ast_node!(Constant, SyntaxKind::Constant);
ast_node!(TypeDecl, SyntaxKind::TypeDecl);
ast_node!(AdviceMap, SyntaxKind::AdviceMap);
ast_node!(BeginBlock, SyntaxKind::BeginBlock);
ast_node!(Procedure, SyntaxKind::Procedure);
ast_node!(Attribute, SyntaxKind::Attribute);
ast_node!(Visibility, SyntaxKind::Visibility);
ast_node!(Signature, SyntaxKind::Signature);
ast_node!(Block, SyntaxKind::Block);
ast_node!(IfOp, SyntaxKind::IfOp);
ast_node!(WhileOp, SyntaxKind::WhileOp);
ast_node!(RepeatOp, SyntaxKind::RepeatOp);
ast_node!(Instruction, SyntaxKind::Instruction);
ast_node!(Path, SyntaxKind::Path);
ast_node!(Expr, SyntaxKind::Expr);
ast_node!(TypeBody, SyntaxKind::TypeBody);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Item {
    ModuleDoc(ModuleDoc),
    Doc(Doc),
    Import(Import),
    Constant(Constant),
    TypeDecl(TypeDecl),
    AdviceMap(AdviceMap),
    BeginBlock(BeginBlock),
    Procedure(Procedure),
}

impl Item {
    pub fn cast(node: SyntaxNode) -> Option<Self> {
        match node.kind() {
            SyntaxKind::ModuleDoc => ModuleDoc::cast(node).map(Self::ModuleDoc),
            SyntaxKind::Doc => Doc::cast(node).map(Self::Doc),
            SyntaxKind::Import => Import::cast(node).map(Self::Import),
            SyntaxKind::Constant => Constant::cast(node).map(Self::Constant),
            SyntaxKind::TypeDecl => TypeDecl::cast(node).map(Self::TypeDecl),
            SyntaxKind::AdviceMap => AdviceMap::cast(node).map(Self::AdviceMap),
            SyntaxKind::BeginBlock => BeginBlock::cast(node).map(Self::BeginBlock),
            SyntaxKind::Procedure => Procedure::cast(node).map(Self::Procedure),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    If(IfOp),
    While(WhileOp),
    Repeat(RepeatOp),
    Instruction(Instruction),
}

impl Operation {
    pub fn cast(node: SyntaxNode) -> Option<Self> {
        match node.kind() {
            SyntaxKind::IfOp => IfOp::cast(node).map(Self::If),
            SyntaxKind::WhileOp => WhileOp::cast(node).map(Self::While),
            SyntaxKind::RepeatOp => RepeatOp::cast(node).map(Self::Repeat),
            SyntaxKind::Instruction => Instruction::cast(node).map(Self::Instruction),
            _ => None,
        }
    }
}

impl SourceFile {
    pub fn items(&self) -> impl Iterator<Item = Item> + '_ {
        self.syntax.children().filter_map(Item::cast)
    }
}

impl Import {
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    pub fn path(&self) -> Option<Path> {
        support::child(&self.syntax)
    }

    pub fn alias_token(&self) -> Option<SyntaxToken> {
        token_after_punctuation(&self.syntax, SyntaxKind::RArrow)
    }
}

impl Constant {
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "const")
    }

    pub fn expr(&self) -> Option<Expr> {
        support::child(&self.syntax)
    }
}

impl TypeDecl {
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    pub fn keyword_token(&self) -> Option<SyntaxToken> {
        self.syntax
            .children_with_tokens()
            .filter_map(|element| element.into_token())
            .find(|token| {
                token.kind() == SyntaxKind::Ident && matches!(token.text(), "type" | "enum")
            })
    }

    pub fn name_token(&self) -> Option<SyntaxToken> {
        let keyword = self.keyword_token()?;
        next_significant_token(&self.syntax, &keyword)
    }

    pub fn body(&self) -> Option<TypeBody> {
        support::child(&self.syntax)
    }
}

impl AdviceMap {
    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "adv_map")
    }

    pub fn value_expr(&self) -> Option<Expr> {
        support::child(&self.syntax)
    }
}

impl BeginBlock {
    pub fn block(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl Procedure {
    pub fn attributes(&self) -> impl Iterator<Item = Attribute> + '_ {
        support::children(&self.syntax)
    }

    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    pub fn signature(&self) -> Option<Signature> {
        support::child(&self.syntax)
    }

    pub fn block(&self) -> Option<Block> {
        support::children(&self.syntax).last()
    }

    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "proc")
    }
}

impl Block {
    pub fn operations(&self) -> impl Iterator<Item = Operation> + '_ {
        self.syntax.children().filter_map(Operation::cast)
    }
}

impl IfOp {
    pub fn then_block(&self) -> Option<Block> {
        support::children(&self.syntax).next()
    }

    pub fn else_block(&self) -> Option<Block> {
        support::children(&self.syntax).nth(1)
    }
}

impl WhileOp {
    pub fn body(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl RepeatOp {
    pub fn body(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl Path {
    pub fn segments(&self) -> impl Iterator<Item = SyntaxToken> + '_ {
        self.syntax
            .children_with_tokens()
            .filter_map(|element| element.into_token())
            .filter(|token| {
                matches!(
                    token.kind(),
                    SyntaxKind::Ident | SyntaxKind::QuotedIdent | SyntaxKind::SpecialIdent
                )
            })
    }
}

impl Expr {
    pub fn significant_tokens(&self) -> impl Iterator<Item = SyntaxToken> + '_ {
        self.syntax
            .children_with_tokens()
            .filter_map(|element| element.into_token())
            .filter(|token| !token.kind().is_trivia())
    }
}

fn token_after_keyword(node: &SyntaxNode, keyword: &str) -> Option<SyntaxToken> {
    let keyword_token = node
        .children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| token.kind() == SyntaxKind::Ident && token.text() == keyword)?;
    next_significant_token(node, &keyword_token)
}

fn token_after_punctuation(node: &SyntaxNode, punctuation: SyntaxKind) -> Option<SyntaxToken> {
    let punctuation_token = node
        .children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| token.kind() == punctuation)?;
    next_significant_token(node, &punctuation_token)
}

fn next_significant_token(node: &SyntaxNode, token: &SyntaxToken) -> Option<SyntaxToken> {
    let mut seen = false;
    for candidate in node.children_with_tokens().filter_map(|element| element.into_token()) {
        if !seen {
            seen = candidate == *token;
            continue;
        }
        if !candidate.kind().is_trivia() {
            return Some(candidate);
        }
    }
    None
}
