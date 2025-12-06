mod error;
mod symbol_table;

use alloc::sync::Arc;

use miden_debug_types::{SourceManager, SourceSpan, Span, Spanned};

use self::symbol_table::LocalSymbolTable;
pub use self::{
    error::SymbolResolutionError,
    symbol_table::{LocalSymbol, SymbolTable},
};
use super::{GlobalItemIndex, ModuleIndex};
use crate::{
    Path, Word,
    ast::{AliasTarget, Ident, ItemIndex},
};

/// Represents the result of resolving a symbol
#[derive(Debug, Clone)]
pub enum SymbolResolution {
    /// The name was resolved to a definition in the same module at the given index
    Local(Span<ItemIndex>),
    /// The name was resolved to a path referring to an item exported from another module
    External(Span<Arc<Path>>),
    /// The name was resolved to a procedure MAST root
    MastRoot(Span<Word>),
    /// The name was resolved to a known definition in with the given global index and absolute path
    Exact {
        gid: GlobalItemIndex,
        path: Span<Arc<Path>>,
    },
    /// The name was resolved to a known module
    Module { id: ModuleIndex, path: Span<Arc<Path>> },
}

impl SymbolResolution {
    pub fn into_global_id(&self) -> Option<GlobalItemIndex> {
        match self {
            Self::Exact { gid, .. } => Some(*gid),
            Self::Local(_) | Self::External(_) | Self::MastRoot(_) | Self::Module { .. } => None,
        }
    }
}

impl Spanned for SymbolResolution {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Local(p) => p.span(),
            Self::External(p) => p.span(),
            Self::MastRoot(p) => p.span(),
            Self::Exact { path, .. } => path.span(),
            Self::Module { path, .. } => path.span(),
        }
    }
}

// LOCAL SYMBOL RESOLVER
// ================================================================================================

/// A resolver for symbol references in the context of some module.
///
/// This resolver does not attempt to resolve external references, aside from expanding any uses
/// of imports in an external path.
///
/// This is used as a low-level symbol resolution primitive in the linker as well.
pub struct LocalSymbolResolver {
    symbols: LocalSymbolTable,
}

impl LocalSymbolResolver {
    /// Create a new resolver using the provided [SymbolTable] and [SourceManager].
    pub fn new<S>(symbols: S, source_manager: Arc<dyn SourceManager>) -> Self
    where
        S: SymbolTable,
    {
        Self {
            symbols: LocalSymbolTable::new(symbols, source_manager),
        }
    }

    /// Expand `path` using `get_import` to resolve a raw symbol name to an import in the current
    /// symbol resolution context.
    ///
    /// Uses the provided [SourceManager] to emit errors that are discovered during expansion.
    #[inline]
    pub fn expand<F>(
        get_import: F,
        path: Span<&Path>,
        source_manager: &dyn SourceManager,
    ) -> Result<SymbolResolution, SymbolResolutionError>
    where
        F: Fn(&str) -> Option<AliasTarget>,
    {
        LocalSymbolTable::expand(get_import, path, source_manager)
    }

    #[inline]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.symbols.source_manager_arc()
    }

    /// Try to resolve `name` to an item, either local or external
    ///
    /// See `SymbolTable::get` for details.
    #[inline]
    pub fn resolve(&self, name: Span<&str>) -> Result<SymbolResolution, SymbolResolutionError> {
        self.symbols.get(name)
    }

    /// Try to resolve `path` to an item, either local or external
    pub fn resolve_path(
        &self,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, SymbolResolutionError> {
        if path.is_absolute() {
            return Ok(SymbolResolution::External(path.map(|p| p.into())));
        }
        log::debug!(target: "local-symbol-resolver", "resolving path '{path}'");
        let (ns, subpath) = path.split_first().expect("invalid item path");
        log::debug!(target: "local-symbol-resolver", "resolving symbol '{ns}'");
        match self.resolve(Span::new(path.span(), ns))? {
            SymbolResolution::External(target) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to import of '{target}'");
                if subpath.is_empty() {
                    log::debug!(target: "local-symbol-resolver", "resolved '{path}' '{target}'");
                    Ok(SymbolResolution::External(target))
                } else {
                    let resolved = target.join(subpath).into();
                    log::debug!(target: "local-symbol-resolver", "resolved '{path}' '{resolved}'");
                    Ok(SymbolResolution::External(Span::new(target.span(), resolved)))
                }
            },
            SymbolResolution::Local(item) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to local item '{item}'");
                if subpath.is_empty() {
                    return Ok(SymbolResolution::Local(item));
                }

                // This is an invalid subpath reference
                log::error!(target: "local-symbol-resolver", "cannot resolve '{subpath}' relative to non-module item");
                Err(SymbolResolutionError::invalid_sub_path(
                    path.span(),
                    item.span(),
                    self.symbols.source_manager(),
                ))
            },
            SymbolResolution::MastRoot(digest) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to procedure root '{digest}'");
                if subpath.is_empty() {
                    return Ok(SymbolResolution::MastRoot(digest));
                }

                // This is an invalid subpath reference
                log::error!(target: "local-symbol-resolver", "cannot resolve '{subpath}' relative to procedure");
                Err(SymbolResolutionError::invalid_sub_path(
                    path.span(),
                    digest.span(),
                    self.symbols.source_manager(),
                ))
            },
            SymbolResolution::Module { id, path, .. } => {
                if subpath.is_empty() {
                    Ok(SymbolResolution::Module { id, path })
                } else {
                    Ok(SymbolResolution::External(path.map(|p| p.join(subpath).into())))
                }
            },
            SymbolResolution::Exact { .. } => unreachable!(),
        }
    }

    /// Get the name of the item at `index`
    ///
    /// This is guaranteed to resolve if `index` is valid, and will panic if not.
    pub fn get_item_name(&self, index: ItemIndex) -> Ident {
        match &self.symbols[index] {
            LocalSymbol::Item { name, .. } => name.clone(),
            LocalSymbol::Import { name, .. } => Ident::from_raw_parts(name.clone()),
        }
    }
}
