use alloc::{string::String, sync::Arc};

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{
    AdviceMapEntry, Alias, Block, Constant, EnumType, Ident, Item, Path, Procedure, SubmoduleDecl,
    TypeAlias, TypeDecl,
};

/// This type represents the top-level forms of a Miden Assembly module
#[derive(Debug, PartialEq, Eq)]
pub enum Form {
    /// A documentation string for the entire module
    ModuleDoc(Span<String>),
    /// A documentation string
    Doc(Span<String>),
    /// An explicit `namespace` declaration
    ///
    /// Only valid when present in the root module of a project target
    Namespace(Span<Arc<Path>>),
    /// An explicit `extern package` declaration
    ///
    /// Only valid when present in the root module of a project target
    ExternPackage(Ident),
    /// A submodule declaration, i.e. `mod foo` or `pub mod foo`
    Submodule(SubmoduleDecl),
    /// A type declaration
    Type(TypeAlias),
    /// An enum type/constant declaration
    Enum(EnumType),
    /// A constant definition, possibly unresolved
    Constant(Constant),
    /// An executable block, represents a program entrypoint
    Begin(Block),
    /// A procedure
    Procedure(Procedure),
    /// A foreign item alias
    Alias(Alias),
    /// An entry into the Advice Map
    AdviceMapEntry(AdviceMapEntry),
}

impl From<Span<String>> for Form {
    fn from(doc: Span<String>) -> Self {
        Self::Doc(doc)
    }
}

impl From<SubmoduleDecl> for Form {
    fn from(value: SubmoduleDecl) -> Self {
        Self::Submodule(value)
    }
}

impl From<TypeAlias> for Form {
    fn from(value: TypeAlias) -> Self {
        Self::Type(value)
    }
}

impl From<EnumType> for Form {
    fn from(value: EnumType) -> Self {
        Self::Enum(value)
    }
}

impl From<Constant> for Form {
    fn from(constant: Constant) -> Self {
        Self::Constant(constant)
    }
}

impl From<Alias> for Form {
    fn from(alias: Alias) -> Self {
        Self::Alias(alias)
    }
}

impl From<Block> for Form {
    fn from(block: Block) -> Self {
        Self::Begin(block)
    }
}

impl From<Item> for Form {
    fn from(item: Item) -> Self {
        match item {
            Item::Alias(item) => Self::Alias(item),
            Item::Constant(item) => Self::Constant(item),
            Item::Type(TypeDecl::Alias(item)) => Self::Type(item),
            Item::Type(TypeDecl::Enum(item)) => Self::Enum(item),
            Item::Procedure(item) => Self::Procedure(item),
        }
    }
}

impl Spanned for Form {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Namespace(spanned) => spanned.span(),
            Self::ExternPackage(spanned) => spanned.span(),
            Self::Submodule(spanned) => spanned.name.span(),
            Self::ModuleDoc(spanned) | Self::Doc(spanned) => spanned.span(),
            Self::Type(spanned) => spanned.span(),
            Self::Enum(spanned) => spanned.span(),
            Self::Constant(Constant { span, .. })
            | Self::AdviceMapEntry(AdviceMapEntry { span, .. }) => *span,
            Self::Begin(spanned) => spanned.span(),
            Self::Procedure(spanned) => spanned.span(),
            Self::Alias(spanned) => spanned.span(),
        }
    }
}
