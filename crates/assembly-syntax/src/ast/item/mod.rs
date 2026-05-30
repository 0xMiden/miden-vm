mod index;
mod items;
mod resolver;

use miden_debug_types::Spanned;

pub use self::{
    index::{GlobalItemIndex, ItemIndex, ModuleIndex},
    items::Item,
    resolver::{
        LocalSymbol, LocalSymbolResolver, SymbolResolution, SymbolResolutionError, SymbolTable,
    },
};
use super::{Ident, Visibility};

#[derive(Debug, Copy, Clone)]
pub enum Declaration<'a> {
    Item(&'a Item),
    Submodule(&'a SubmoduleDecl),
}

impl Spanned for Declaration<'_> {
    fn span(&self) -> miden_debug_types::SourceSpan {
        match self {
            Self::Item(item) => item.span(),
            Self::Submodule(decl) => decl.name.span(),
        }
    }
}

/// Represents a submodule declaration in a [Module], i.e. `mod foo` or `pub mod foo`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmoduleDecl {
    /// The visibility of the submodule outside the containing namespace.
    ///
    /// A private submodule is visible only to:
    ///
    /// * It's parent
    /// * It's siblings and their descendants
    ///
    /// A public submodule is visible to everyone.
    pub visibility: Visibility,
    /// The name of the submodule
    ///
    /// The full path of the submodule is derived from the path of its parent module
    pub name: Ident,
}
