use alloc::boxed::Box;
use core::cell::{Cell, RefCell};

use miden_assembly_syntax::{
    ast::{self, GlobalItemIndex, Ident, Visibility},
    library::ItemInfo,
};

use super::LinkStatus;

/// A [Symbol] is a named, linkable item defined within a module.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// The name of the symbol in it's containing module.
    name: Ident,
    /// The external visibility of the symbol
    visibility: Visibility,
    /// The link status of the symbol, i.e. unlinked, partially, or fully linked.
    status: Cell<LinkStatus>,
    /// The type of item associated with this symbol.
    item: SymbolItem,
}

/// A [SymbolItem] represents the type of item associated with a [Symbol].
#[derive(Debug, Clone)]
pub enum SymbolItem {
    /// An alias of an externally-defined item
    Alias {
        /// The original alias item
        alias: ast::Alias,
        /// Once the alias has been resolved, we set this to `Some(target_gid)` so that we can
        /// simply shortcut to the resolved target once known.
        resolved: Cell<Option<GlobalItemIndex>>,
    },
    /// A constant declaration in AST form
    Constant(ast::Constant),
    /// A type or enum declaration in AST form
    Type(ast::TypeDecl),
    /// Procedure symbols are wrapped in a `RefCell` to allow us to mutate the procedure body when
    /// linking any externally-defined symbols it contains.
    Procedure(RefCell<Box<ast::Procedure>>),
    /// An already-assembled item
    Compiled(ItemInfo),
}

impl Symbol {
    /// Create a new [Symbol].
    #[inline]
    pub fn new(name: Ident, visibility: Visibility, status: LinkStatus, item: SymbolItem) -> Self {
        Self {
            name,
            visibility,
            status: Cell::new(status),
            item,
        }
    }

    /// Get the module-local name of this symbol
    #[inline(always)]
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Get the external visibility of this symbol
    #[inline(always)]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Get the item associated with this symbol
    #[inline(always)]
    pub fn item(&self) -> &SymbolItem {
        &self.item
    }

    /// Get the current link status of this symbol
    #[inline(always)]
    pub fn status(&self) -> LinkStatus {
        self.status.get()
    }

    /// Set the link status of this symbol
    #[inline]
    pub fn set_status(&self, status: LinkStatus) {
        self.status.set(status);
    }

    /// Returns true if this symbol has not yet been visited by the linker.
    #[inline]
    pub fn is_unlinked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Unlinked)
    }

    /// Returns true if this symbol is fully-linked.
    #[inline]
    pub fn is_linked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Linked)
    }

    /// Returns true if this symbol represents a procedure definition.
    pub fn is_procedure(&self) -> bool {
        matches!(
            &self.item,
            SymbolItem::Compiled(ItemInfo::Procedure(_)) | SymbolItem::Procedure(_)
        )
    }
}
