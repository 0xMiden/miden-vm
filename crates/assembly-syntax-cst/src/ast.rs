/// Re-export of rowan's typed-node trait for CST wrappers.
pub use rowan::ast::AstNode;
use rowan::ast::support;

use crate::syntax::{MasmLanguage, SyntaxKind, SyntaxNode, SyntaxToken};

macro_rules! ast_node {
    ($(#[$meta:meta])* $name:ident, $kind:path) => {
        $(#[$meta])*
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

ast_node!(
    #[doc = "The root node for a parsed MASM source file."]
    SourceFile,
    SyntaxKind::SourceFile
);
ast_node!(
    #[doc = "A leading `#!` documentation line classified as module-level documentation."]
    ModuleDoc,
    SyntaxKind::ModuleDoc
);
ast_node!(
    #[doc = "A `#!` documentation line attached to the following item."]
    Doc,
    SyntaxKind::Doc
);
ast_node!(
    #[doc = "A `use` item."]
    Import,
    SyntaxKind::Import
);
ast_node!(
    #[doc = "A `const` item."]
    Constant,
    SyntaxKind::Constant
);
ast_node!(
    #[doc = "A `type` or `enum` item."]
    TypeDecl,
    SyntaxKind::TypeDecl
);
ast_node!(
    #[doc = "An `adv_map` item."]
    AdviceMap,
    SyntaxKind::AdviceMap
);
ast_node!(
    #[doc = "A top-level `begin` block."]
    BeginBlock,
    SyntaxKind::BeginBlock
);
ast_node!(
    #[doc = "A `proc` item together with its attributes and body."]
    Procedure,
    SyntaxKind::Procedure
);
ast_node!(
    #[doc = "An attribute attached to a procedure."]
    Attribute,
    SyntaxKind::Attribute
);
ast_node!(
    #[doc = "A visibility marker such as `pub`."]
    Visibility,
    SyntaxKind::Visibility
);
ast_node!(
    #[doc = "A procedure signature node."]
    Signature,
    SyntaxKind::Signature
);
ast_node!(
    #[doc = "A structured operation body."]
    Block,
    SyntaxKind::Block
);
ast_node!(
    #[doc = "An `if.true` or `if.false` structured operation."]
    IfOp,
    SyntaxKind::IfOp
);
ast_node!(
    #[doc = "A `while.true` structured operation."]
    WhileOp,
    SyntaxKind::WhileOp
);
ast_node!(
    #[doc = "A `repeat.<count>` structured operation."]
    RepeatOp,
    SyntaxKind::RepeatOp
);
ast_node!(
    #[doc = "A single instruction line or grouped same-line instruction sequence."]
    Instruction,
    SyntaxKind::Instruction
);
ast_node!(
    #[doc = "A path-like token group used in imports and invocation targets."]
    Path,
    SyntaxKind::Path
);
ast_node!(
    #[doc = "A lossless expression token group."]
    Expr,
    SyntaxKind::Expr
);
ast_node!(
    #[doc = "The body of a `type` or `enum` declaration."]
    TypeBody,
    SyntaxKind::TypeBody
);

/// Any top-level item that can appear beneath the CST root.
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
    /// Attempts to cast a raw syntax node to a typed top-level item wrapper.
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

/// Any operation that can appear directly within a CST block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    If(IfOp),
    While(WhileOp),
    Repeat(RepeatOp),
    Instruction(Instruction),
}

impl Operation {
    /// Attempts to cast a raw syntax node to a typed block-operation wrapper.
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
    /// Returns the top-level items in source order.
    pub fn items(&self) -> impl Iterator<Item = Item> + '_ {
        self.syntax.children().filter_map(Item::cast)
    }
}

impl Import {
    /// Returns the optional visibility marker for this import.
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    /// Returns the imported path or MAST-root target token group.
    pub fn path(&self) -> Option<Path> {
        support::child(&self.syntax)
    }

    /// Returns the alias name token following `->`, if present.
    pub fn alias_token(&self) -> Option<SyntaxToken> {
        token_after_punctuation(&self.syntax, SyntaxKind::RArrow)
    }
}

impl Constant {
    /// Returns the optional visibility marker for this constant.
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    /// Returns the constant name token.
    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "const")
    }

    /// Returns the value expression for this constant.
    pub fn expr(&self) -> Option<Expr> {
        support::child(&self.syntax)
    }
}

impl TypeDecl {
    /// Returns the optional visibility marker for this declaration.
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    /// Returns the `type` or `enum` keyword token for this declaration.
    pub fn keyword_token(&self) -> Option<SyntaxToken> {
        self.syntax
            .children_with_tokens()
            .filter_map(|element| element.into_token())
            .find(|token| {
                token.kind() == SyntaxKind::Ident && matches!(token.text(), "type" | "enum")
            })
    }

    /// Returns the declared type name token.
    pub fn name_token(&self) -> Option<SyntaxToken> {
        let keyword = self.keyword_token()?;
        next_significant_token(&self.syntax, &keyword)
    }

    /// Returns the body node for this declaration.
    pub fn body(&self) -> Option<TypeBody> {
        support::child(&self.syntax)
    }
}

impl AdviceMap {
    /// Returns the advice-map name token.
    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "adv_map")
    }

    /// Returns the advice-map value expression.
    pub fn value_expr(&self) -> Option<Expr> {
        support::child(&self.syntax)
    }
}

impl BeginBlock {
    /// Returns the block body for this top-level `begin` item.
    pub fn block(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl Procedure {
    /// Returns the attributes attached to this procedure in source order.
    pub fn attributes(&self) -> impl Iterator<Item = Attribute> + '_ {
        support::children(&self.syntax)
    }

    /// Returns the optional visibility marker for this procedure.
    pub fn visibility(&self) -> Option<Visibility> {
        support::child(&self.syntax)
    }

    /// Returns the signature node for this procedure.
    pub fn signature(&self) -> Option<Signature> {
        support::child(&self.syntax)
    }

    /// Returns the body block for this procedure.
    pub fn block(&self) -> Option<Block> {
        support::children(&self.syntax).last()
    }

    /// Returns the procedure name token.
    pub fn name_token(&self) -> Option<SyntaxToken> {
        token_after_keyword(&self.syntax, "proc")
    }
}

impl Block {
    /// Returns the operations contained in this block.
    pub fn operations(&self) -> impl Iterator<Item = Operation> + '_ {
        self.syntax.children().filter_map(Operation::cast)
    }
}

impl IfOp {
    /// Returns the first block in this `if`, which is the syntactic then-branch.
    pub fn then_block(&self) -> Option<Block> {
        support::children(&self.syntax).next()
    }

    /// Returns the optional syntactic else-branch block.
    pub fn else_block(&self) -> Option<Block> {
        support::children(&self.syntax).nth(1)
    }
}

impl WhileOp {
    /// Returns the loop body.
    pub fn body(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl RepeatOp {
    /// Returns the repeated body.
    pub fn body(&self) -> Option<Block> {
        support::child(&self.syntax)
    }
}

impl Path {
    /// Returns the non-trivia path segment tokens in source order.
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
    /// Returns all non-trivia tokens in this expression subtree.
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
