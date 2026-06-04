/// Re-export of rowan's typed-node trait for CST wrappers.
pub use rowan::ast::AstNode;
use rowan::ast::support;

use crate::syntax::{MasmLanguage, SyntaxKind, SyntaxNode, SyntaxToken};

pub trait AstNodeExt: AstNode<Language = MasmLanguage> {
    /// Get a short description of this node
    fn describe(&self) -> &'static str;

    /// Collects the direct, non-trivia tokens under `node`.
    fn significant_tokens(&self) -> impl Iterator<Item = SyntaxToken>;
}

macro_rules! ast_node {
    ($(#[$meta:meta])* $name:ident, $kind:path, $description:literal) => {
        __ast_node!($(#[$meta])* $name, $kind, $description, significant_tokens);
    };

    ($(#[$meta:meta])* $name:ident, $kind:path, $description:literal, recursive = true) => {
        __ast_node!($(#[$meta])* $name, $kind, $description, significant_tokens_recursive);
    };
}

macro_rules! __ast_node {
    ($(#[$meta:meta])* $name:ident, $kind:path, $description:literal, $significant_tokens:ident) => {
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

        impl $name {
            /// Collects the direct, non-trivia tokens under `node`.
            #[inline]
            pub fn significant_tokens(&self) -> impl Iterator<Item = SyntaxToken> {
                <Self as AstNodeExt>::significant_tokens(self)
            }
        }

        impl AstNodeExt for $name {
            #[inline]
            fn describe(&self) -> &'static str {
                $description
            }

            #[inline]
            fn significant_tokens(&self) -> impl Iterator<Item = SyntaxToken> {
                $significant_tokens(self.syntax())
            }
        }
    };
}

ast_node!(
    #[doc = "The root node for a parsed MASM source file."]
    SourceFile,
    SyntaxKind::SourceFile,
    "source file"
);
ast_node!(
    #[doc = "A `#!` documentation line. Lowering decides whether a contiguous group becomes module-level or item-level documentation."]
    Doc,
    SyntaxKind::Doc,
    "doc comment"
);
ast_node!(
    #[doc = "A `use` item."]
    Import,
    SyntaxKind::Import,
    "import"
);
ast_node!(
    #[doc = "A `const` item."]
    Constant,
    SyntaxKind::Constant,
    "constant declaration"
);
ast_node!(
    #[doc = "A `type` or `enum` item."]
    TypeDecl,
    SyntaxKind::TypeDecl,
    "type declaration"
);
ast_node!(
    #[doc = "An `adv_map` item."]
    AdviceMap,
    SyntaxKind::AdviceMap,
    "advice map entry declaration",
    recursive = true
);
ast_node!(
    #[doc = "A top-level `begin` block."]
    BeginBlock,
    SyntaxKind::BeginBlock,
    "begin"
);
ast_node!(
    #[doc = "A `proc` item together with its attributes and body."]
    Procedure,
    SyntaxKind::Procedure,
    "procedure declaration"
);
ast_node!(
    #[doc = "An attribute attached to a procedure."]
    Attribute,
    SyntaxKind::Attribute,
    "attribute"
);
ast_node!(
    #[doc = "A visibility marker such as `pub`."]
    Visibility,
    SyntaxKind::Visibility,
    "visibility modifier"
);
ast_node!(
    #[doc = "A procedure signature node."]
    Signature,
    SyntaxKind::Signature,
    "type signature"
);
ast_node!(
    #[doc = "A structured operation body."]
    Block,
    SyntaxKind::Block,
    "block"
);
ast_node!(
    #[doc = "An `if.true` or `if.false` structured operation."]
    IfOp,
    SyntaxKind::IfOp,
    "if statement"
);
ast_node!(
    #[doc = "A `while.true` structured operation."]
    WhileOp,
    SyntaxKind::WhileOp,
    "while loop"
);
ast_node!(
    #[doc = "A `do`..`while`..`end` structured operation (tail-controlled loop)."]
    DoWhileOp,
    SyntaxKind::DoWhileOp,
    "do-while loop"
);
ast_node!(
    #[doc = "A `repeat.<count>` structured operation."]
    RepeatOp,
    SyntaxKind::RepeatOp,
    "repeat"
);
ast_node!(
    #[doc = "A single instruction line or grouped same-line instruction sequence."]
    Instruction,
    SyntaxKind::Instruction,
    "instruction"
);
ast_node!(
    #[doc = "A path-like token group used in imports and invocation targets."]
    Path,
    SyntaxKind::Path,
    "symbol path"
);
ast_node!(
    #[doc = "A lossless expression token group."]
    Expr,
    SyntaxKind::Expr,
    "expression"
);
ast_node!(
    #[doc = "The body of a `type` or `enum` declaration."]
    TypeBody,
    SyntaxKind::TypeBody,
    "type definition"
);

/// Any top-level item that can appear beneath the CST root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Item {
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
    DoWhile(DoWhileOp),
    Repeat(RepeatOp),
    Instruction(Instruction),
}

impl Operation {
    /// Attempts to cast a raw syntax node to a typed block-operation wrapper.
    pub fn cast(node: SyntaxNode) -> Option<Self> {
        match node.kind() {
            SyntaxKind::IfOp => IfOp::cast(node).map(Self::If),
            SyntaxKind::WhileOp => WhileOp::cast(node).map(Self::While),
            SyntaxKind::DoWhileOp => DoWhileOp::cast(node).map(Self::DoWhile),
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
            .filter_map(rowan::NodeOrToken::into_token)
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

impl DoWhileOp {
    /// Returns the loop body (the block between `do` and `while`).
    pub fn body(&self) -> Option<Block> {
        support::children(&self.syntax).next()
    }

    /// Returns the condition block (the block between `while` and `end`).
    pub fn condition(&self) -> Option<Block> {
        support::children(&self.syntax).nth(1)
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
            .filter_map(rowan::NodeOrToken::into_token)
            .filter(|token| {
                matches!(
                    token.kind(),
                    SyntaxKind::Ident | SyntaxKind::QuotedIdent | SyntaxKind::SpecialIdent
                )
            })
    }
}

fn token_after_keyword(node: &SyntaxNode, keyword: &str) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .skip_while(|token| !(token.kind() == SyntaxKind::Ident && token.text() == keyword))
        .skip(1)
        .find(|token| !token.kind().is_trivia())
}

fn token_after_punctuation(node: &SyntaxNode, punctuation: SyntaxKind) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .skip_while(|token| token.kind() != punctuation)
        .skip(1)
        .find(|token| !token.kind().is_trivia())
}

/// Collects the direct, non-trivia tokens under `node`.
fn significant_tokens(node: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> {
    node.children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
}

/// Collects all non-trivia tokens in `node`'s subtree.
///
/// Some fragments nest their significant syntax under container nodes, so direct-child token
/// collection is not sufficient.
fn significant_tokens_recursive(node: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> {
    node.descendants_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
}

fn next_significant_token(node: &SyntaxNode, token: &SyntaxToken) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .skip_while(|t| t != token)
        .skip(1)
        .find(|token| !token.kind().is_trivia())
}
