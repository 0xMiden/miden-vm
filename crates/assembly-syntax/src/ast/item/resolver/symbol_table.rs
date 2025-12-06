use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_debug_types::{SourceManager, Span, Spanned};

use super::{SymbolResolution, SymbolResolutionError};
use crate::{
    Path,
    ast::{AliasTarget, Ident, ItemIndex},
};

/// This trait abstracts over any type which acts as a symbol table, e.g. a [crate::ast::Module].
pub trait SymbolTable {
    /// The concrete iterator type for the container.
    type SymbolIter: Iterator<Item = LocalSymbol>;

    /// Get an iterator over the symbols in this symbol table, using the provided [SourceManager]
    /// to emit errors for symbols which are invalid/unresolvable.
    fn symbols(&self, source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter;
}

impl SymbolTable for &crate::library::ModuleInfo {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, _source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        let module_items = self.items();
        let mut items = Vec::with_capacity(module_items.len());

        for (index, item) in module_items {
            let name = item.name().clone();
            let span = name.span();

            assert_eq!(index.as_usize(), items.len());
            items.push(LocalSymbol::Item {
                name,
                resolved: SymbolResolution::Local(Span::new(span, index)),
            });
        }

        items.into_iter()
    }
}

impl SymbolTable for &crate::ast::Module {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        use crate::ast::{AliasTarget, Export};

        let mut items = Vec::with_capacity(self.items.len());

        for (i, item) in self.items.iter().enumerate() {
            let id = ItemIndex::new(i);
            let name = item.name().clone();
            let span = name.span();
            let name = name.into_inner();

            if let Export::Alias(alias) = item {
                match alias.target() {
                    AliasTarget::MastRoot(root) => {
                        items.push(LocalSymbol::Import {
                            name: Span::new(span, name),
                            resolution: Ok(SymbolResolution::MastRoot(*root)),
                        });
                    },
                    AliasTarget::Path(path) => {
                        let expanded = LocalSymbolTable::expand(
                            |name| self.get_import(name).map(|alias| alias.target().clone()),
                            path.as_deref(),
                            &source_manager,
                        );
                        items.push(LocalSymbol::Import {
                            name: Span::new(span, name),
                            resolution: expanded,
                        });
                    },
                }
            } else {
                items.push(LocalSymbol::Item {
                    name: Ident::from_raw_parts(Span::new(span, name)),
                    resolved: SymbolResolution::Local(Span::new(span, id)),
                });
            }
        }

        items.into_iter()
    }
}

/// Represents a symbol within the context of a single module
#[derive(Debug)]
pub enum LocalSymbol {
    /// This symbol is a declaration, with the given resolution.
    Item { name: Ident, resolved: SymbolResolution },
    /// This symbol is an import of an externally-defined item.
    Import {
        name: Span<Arc<str>>,
        resolution: Result<SymbolResolution, SymbolResolutionError>,
    },
}

impl LocalSymbol {
    pub fn name(&self) -> &str {
        match self {
            Self::Item { name, .. } => name.as_str(),
            Self::Import { name, .. } => name,
        }
    }
}

/// The common local symbol table/registry implementation
pub(super) struct LocalSymbolTable {
    source_manager: Arc<dyn SourceManager>,
    symbols: BTreeMap<Arc<str>, ItemIndex>,
    items: Vec<LocalSymbol>,
}

impl core::ops::Index<ItemIndex> for LocalSymbolTable {
    type Output = LocalSymbol;

    #[inline(always)]
    fn index(&self, index: ItemIndex) -> &Self::Output {
        &self.items[index.as_usize()]
    }
}

impl LocalSymbolTable {
    pub fn new<S>(iter: S, source_manager: Arc<dyn SourceManager>) -> Self
    where
        S: SymbolTable,
    {
        let mut symbols = BTreeMap::default();
        let mut items = Vec::with_capacity(16);

        for (i, symbol) in iter.symbols(source_manager.clone()).enumerate() {
            log::debug!(target: "symbol-table::new", "registering {} symbol: {}", match symbol {
                LocalSymbol::Item { .. } => "local",
                LocalSymbol::Import { .. } => "imported",
            }, symbol.name());

            let id = ItemIndex::new(i);
            let name = match &symbol {
                LocalSymbol::Item { name, .. } => name.clone().into_inner(),
                LocalSymbol::Import { name, .. } => name.clone().into_inner(),
            };

            symbols.insert(name, id);
            items.push(symbol);
        }

        Self { source_manager, symbols, items }
    }

    #[inline(always)]
    pub fn source_manager(&self) -> &dyn SourceManager {
        &self.source_manager
    }

    #[inline(always)]
    pub fn source_manager_arc(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }
}

impl LocalSymbolTable {
    /// Get the symbol `name` from this table, if present.
    ///
    /// Returns `Ok(None)` if the symbol is undefined in this table.
    ///
    /// Returns `Ok(Some)` if the symbol is defined, and we were able to resolve it to either a
    /// local or external item without encountering any issues.
    ///
    /// Returns `Err` if the symbol cannot possibly be resolved, e.g. the expanded path refers to
    /// a child of an item that cannot have children, such as a procedure.
    pub fn get(&self, name: Span<&str>) -> Result<SymbolResolution, SymbolResolutionError> {
        log::debug!(target: "symbol-table", "attempting to resolve '{name}'");
        let (span, name) = name.into_parts();
        let Some(item) = self.symbols.get(name).copied() else {
            return Err(SymbolResolutionError::undefined(span, &self.source_manager));
        };
        match &self.items[item.as_usize()] {
            LocalSymbol::Item { resolved, .. } => {
                log::debug!(target: "symbol-table", "resolved '{name}' to {resolved:?}");
                Ok(resolved.clone())
            },
            LocalSymbol::Import { name, resolution } => {
                log::debug!(target: "symbol-table", "'{name}' refers to an import");
                match resolution {
                    Ok(resolved) => {
                        log::debug!(target: "symbol-table", "resolved '{name}' to {resolved:?}");
                        Ok(resolved.clone())
                    },
                    Err(err) => {
                        log::error!(target: "symbol-table", "resolution of '{name}' failed: {err}");
                        Err(err.clone())
                    },
                }
            },
        }
    }

    /// Expand `path` in the context of `module`.
    ///
    /// Our aim here is to replace any leading import-relative path component with the corresponding
    /// target path, recursively.
    ///
    /// Doing so ensures that code like the following works as expected:
    ///
    /// ```masm,ignore
    /// use mylib::foo
    /// use foo::bar->baz
    ///
    /// begin
    ///     exec.baz::p
    /// end
    /// ```
    ///
    /// In the scenario above, calling `expand` on `baz::p` would proceed as follows:
    ///
    /// 1. `path` is `baz::p` a. We split `path` into `baz` and `p` (i.e. `module_name` and `rest`)
    ///    b. We look for an import of the symbol `baz`, and find `use foo::bar->baz` c. The target
    ///    of the import is `foo::bar`, which we recursively call `expand` on
    /// 2. `path` is now `foo::bar` a. We split `path` into `foo` and `bar` b. We look for an import
    ///    of `foo`, and find `use mylib::foo` c. The target of the import is `mylib::foo`, which we
    ///    recursively call `expand` on
    /// 3. `path` is now `mylib::foo` a. We split `path` into `mylib` and `foo` b. We look for an
    ///    import of `mylib`, and do not find one. c. Since there is no import, we consider
    ///    `mylib::foo` to be fully expanded and return it
    /// 4. We've now expanded `foo` into `mylib::foo`, and so expansion of `foo::bar` is completed
    ///    by joining `bar` to `mylib::foo`, and returning `mylib::foo::bar`.
    /// 5. We've now expanded `baz` into `mylib::foo::bar`, and so the expansion of `baz::p` is
    ///    completed by joining `p` to `mylib::foo::bar` and returning `mylib::foo::bar::p`.
    /// 6. We're done, having successfully resolved `baz::p` to its full expansion
    ///    `mylib::foo::bar::p`
    pub fn expand<F>(
        get_import: F,
        path: Span<&Path>,
        source_manager: &dyn SourceManager,
    ) -> Result<SymbolResolution, SymbolResolutionError>
    where
        F: Fn(&str) -> Option<AliasTarget>,
    {
        let (module_name, rest) = path.split_first().unwrap();
        if let Some(target) = get_import(module_name) {
            match target {
                AliasTarget::MastRoot(digest) if rest.is_empty() => {
                    Ok(SymbolResolution::MastRoot(digest))
                },
                AliasTarget::MastRoot(digest) => Err(SymbolResolutionError::invalid_alias_target(
                    digest.span(),
                    path.span(),
                    source_manager,
                )),
                // If we have an import like `use lib::lib`, we cannot refer to the base `lib` any
                // longer, as it has been shadowed; any attempt to further expand the path will
                // recurse infinitely.
                //
                // For now, we handle this by simply stopping further expansion. In the future, we
                // may want to refine module.get_import to allow passing an exclusion list, so that
                // we can avoid recursing on the same import in an infinite loop.
                AliasTarget::Path(shadowed) if shadowed.as_deref() == path => {
                    Ok(SymbolResolution::External(shadowed.clone()))
                },
                AliasTarget::Path(path) => {
                    let path = path.clone();
                    let resolved = Self::expand(get_import, path.as_deref(), source_manager)?;
                    match resolved {
                        SymbolResolution::Module { id, path } => {
                            // We can consider this path fully-resolved, and mark it absolute, if it
                            // is not already
                            if rest.is_empty() {
                                Ok(SymbolResolution::Module { id, path })
                            } else {
                                Ok(SymbolResolution::External(path.map(|p| p.join(rest).into())))
                            }
                        },
                        SymbolResolution::External(resolved) => {
                            // We can consider this path fully-resolved, and mark it absolute, if it
                            // is not already
                            Ok(SymbolResolution::External(
                                resolved.map(|p| p.to_absolute().join(rest).into()),
                            ))
                        },
                        res @ (SymbolResolution::MastRoot(_)
                        | SymbolResolution::Local(_)
                        | SymbolResolution::Exact { .. })
                            if rest.is_empty() =>
                        {
                            Ok(res)
                        },
                        SymbolResolution::MastRoot(digest) => {
                            Err(SymbolResolutionError::invalid_alias_target(
                                digest.span(),
                                path.span(),
                                source_manager,
                            ))
                        },
                        SymbolResolution::Exact { path: item_path, .. } => {
                            Err(SymbolResolutionError::invalid_alias_target(
                                item_path.span(),
                                path.span(),
                                source_manager,
                            ))
                        },
                        SymbolResolution::Local(item) => {
                            Err(SymbolResolutionError::invalid_alias_target(
                                item.span(),
                                path.span(),
                                source_manager,
                            ))
                        },
                    }
                },
            }
        } else {
            // We can consider this path fully-resolved, and mark it absolute, if it is not already
            Ok(SymbolResolution::External(path.map(|p| p.to_absolute().into_owned().into())))
        }
    }
}
