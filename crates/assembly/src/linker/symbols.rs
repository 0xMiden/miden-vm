use alloc::{boxed::Box, sync::Arc};
use core::cell::{Cell, RefCell};

use miden_assembly_syntax::{
    Path,
    ast::{self, GlobalItemIndex, Ident, ImportKind, Visibility},
    debuginfo::{SourceSpan, Span, Spanned},
    module::ItemInfo,
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

/// An import declared by a module.
#[derive(Debug, Clone)]
pub struct Import {
    /// The original import declaration.
    decl: ast::Import,
    /// Once this import has been resolved to a concrete item, cache the target id.
    resolved: Cell<Option<GlobalItemIndex>>,
}

/// A [SymbolItem] represents the type of item associated with a [Symbol].
#[derive(Debug, Clone)]
pub enum SymbolItem {
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

impl Import {
    /// Create a new [Import].
    #[inline]
    pub fn new(decl: ast::Import) -> Self {
        Self { decl, resolved: Cell::new(None) }
    }

    /// Get the import declaration.
    #[inline(always)]
    pub fn decl(&self) -> &ast::Import {
        &self.decl
    }

    /// Get the import kind.
    #[inline(always)]
    pub fn kind(&self) -> ImportKind {
        self.decl.kind()
    }

    /// Get the local name bound by this import.
    #[inline(always)]
    pub fn local_name(&self) -> &Ident {
        self.decl.local_name()
    }

    /// Get the import visibility.
    #[inline(always)]
    pub fn visibility(&self) -> Visibility {
        self.decl.visibility()
    }

    /// Get the source span covering this import.
    #[inline(always)]
    pub fn span(&self) -> SourceSpan {
        self.decl.span()
    }

    /// Get the target module path for this import.
    #[inline(always)]
    pub fn module_path(&self) -> Span<&Path> {
        self.decl.module_path()
    }

    /// Get the full target path for this import.
    pub fn target_path(&self) -> Span<Arc<Path>> {
        match &self.decl {
            ast::Import::Module(import) => {
                let path = import.module_path();
                Span::new(path.span(), Arc::from(*path))
            },
            ast::Import::Item(import) => import.target_path(),
        }
    }

    /// Get the cached resolved concrete item, if known.
    #[inline(always)]
    pub fn resolved(&self) -> Option<GlobalItemIndex> {
        self.resolved.get()
    }

    /// Set the cached resolved concrete item.
    #[inline]
    pub fn set_resolved(&self, resolved: GlobalItemIndex) {
        self.resolved.set(Some(resolved));
    }
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
