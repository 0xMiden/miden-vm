use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_debug_types::{SourceManager, SourceSpan, Span, Spanned};

use super::{SymbolResolution, SymbolResolutionError};
use crate::ast::{Ident, Import, ItemIndex};

/// This trait abstracts over any type which acts as a symbol table, e.g. a [crate::ast::Module].
///
/// Resolver construction uses [Self::checked_symbols], which must either return the full symbol
/// set or a structured error.
pub trait SymbolTable {
    /// The concrete iterator type for the container.
    type SymbolIter: Iterator<Item = LocalSymbol>;

    /// Get an iterator over the symbols in this symbol table, using the provided [SourceManager]
    /// to emit errors for symbols which are invalid/unresolvable.
    fn symbols(&self, source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter;

    /// Get an iterator over the symbols in this symbol table, returning a structured error if the
    /// full symbol set cannot be represented exactly.
    ///
    /// Override this when exact resolver construction needs validation, such as rejecting oversized
    /// symbol sets.
    fn checked_symbols(
        &self,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self::SymbolIter, SymbolResolutionError> {
        Ok(self.symbols(source_manager))
    }
}

impl SymbolTable for &crate::module::ModuleDescriptor {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, _source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        let mut items = Vec::with_capacity(self.raw_items().len());

        for (i, item) in self.raw_items().iter().enumerate() {
            let name = item.name().clone();
            let span = name.span();
            items.push(LocalSymbol::Item {
                name,
                resolved: SymbolResolution::Local(Span::new(span, ItemIndex::new(i))),
            });
        }

        items.into_iter()
    }

    fn checked_symbols(
        &self,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self::SymbolIter, SymbolResolutionError> {
        if self.raw_items().len() > ItemIndex::MAX_ITEMS {
            Err(SymbolResolutionError::too_many_items_in_module(
                SourceSpan::UNKNOWN,
                &*source_manager,
            ))
        } else {
            Ok(self.symbols(source_manager))
        }
    }
}

impl SymbolTable for &crate::ast::Module {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, _source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        let mut items = Vec::with_capacity(self.items.len() + self.imports.len());

        for (i, item) in self.items.iter().enumerate() {
            let id = ItemIndex::new(i);
            let name = item.name().clone();
            let span = name.span();
            let name = name.into_inner();

            items.push(LocalSymbol::Item {
                name: Ident::from_raw_parts(Span::new(span, name)),
                resolved: SymbolResolution::Local(Span::new(span, id)),
            });
        }

        items.extend(self.imports.iter().filter_map(|import| {
            let Import::Item(item) = import else {
                return None;
            };
            let local_name = import.local_name().clone();
            let span = local_name.span();
            let name = Span::new(span, local_name.into_inner());
            Some(LocalSymbol::Import {
                name,
                resolution: Ok(SymbolResolution::External(item.target_path())),
            })
        }));

        items.into_iter()
    }

    fn checked_symbols(
        &self,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self::SymbolIter, SymbolResolutionError> {
        if self.items.len() + self.imports.len() > ItemIndex::MAX_ITEMS {
            Err(SymbolResolutionError::too_many_items_in_module(self.span(), &*source_manager))
        } else {
            Ok(self.symbols(source_manager))
        }
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
    fn build<I>(iter: I, source_manager: Arc<dyn SourceManager>) -> Self
    where
        I: Iterator<Item = LocalSymbol>,
    {
        let mut symbols = BTreeMap::default();
        let mut items = Vec::with_capacity(16);

        for (i, symbol) in iter.enumerate() {
            let id = ItemIndex::try_new(i)
                .expect("symbol iterators used by LocalSymbolTable::build must be pre-validated");
            let symbol = match symbol {
                LocalSymbol::Item {
                    name,
                    resolved: SymbolResolution::Local(local),
                } => LocalSymbol::Item {
                    name,
                    resolved: SymbolResolution::Local(Span::new(local.span(), id)),
                },
                symbol => symbol,
            };
            log::debug!(target: "symbol-table::new", "registering {} symbol: {}", match symbol {
                LocalSymbol::Item { .. } => "local",
                LocalSymbol::Import { .. } => "imported",
            }, symbol.name());
            let name = match &symbol {
                LocalSymbol::Item { name, .. } => name.clone().into_inner(),
                LocalSymbol::Import { name, .. } => name.clone().into_inner(),
            };

            if let Some(prev) = symbols.get(&name).copied() {
                debug_assert!(
                    false,
                    "duplicate symbol '{name}' reached local resolver construction (previous={prev:?}, current={id:?})"
                );
            } else {
                symbols.insert(name.clone(), id);
            }
            items.push(symbol);
        }

        Self { source_manager, symbols, items }
    }

    pub fn new<S>(
        iter: S,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, SymbolResolutionError>
    where
        S: SymbolTable,
    {
        let symbols = iter.checked_symbols(source_manager.clone())?;
        Ok(Self::build(symbols, source_manager))
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
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_debug_types::DefaultSourceManager;

    use super::*;
    use crate::Path;

    #[test]
    fn checked_symbols_rejects_oversized_module() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut module =
            crate::ast::Module::new(crate::ast::ModuleKind::Library, Path::new("::m::huge"));

        for i in 0..=ItemIndex::MAX_ITEMS {
            module.items.push(crate::ast::Item::Constant(crate::ast::Constant::new(
                SourceSpan::UNKNOWN,
                crate::ast::Visibility::Private,
                Ident::new(format!("A{i}")).expect("valid identifier"),
                crate::ast::ConstantExpr::Int(Span::unknown(crate::parser::IntValue::from(0u8))),
            )));
        }

        let result = (&module).checked_symbols(source_manager);

        assert!(matches!(result, Err(SymbolResolutionError::TooManyItemsInModule { .. })));
    }

    #[test]
    fn checked_symbols_guard_custom_symbol_table_exact() {
        struct ExactTooManySymbols;

        impl SymbolTable for ExactTooManySymbols {
            type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

            fn symbols(&self, _source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
                panic!("exact construction must not request unchecked symbols")
            }

            fn checked_symbols(
                &self,
                source_manager: Arc<dyn SourceManager>,
            ) -> Result<Self::SymbolIter, SymbolResolutionError> {
                Err(SymbolResolutionError::too_many_items_in_module(
                    SourceSpan::UNKNOWN,
                    &*source_manager,
                ))
            }
        }

        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let result = LocalSymbolTable::new(ExactTooManySymbols, source_manager);

        assert!(matches!(result, Err(SymbolResolutionError::TooManyItemsInModule { .. })));
    }

    #[cfg(test)]
    struct DuplicateSymbolsForInvariantTest;

    #[cfg(test)]
    impl SymbolTable for DuplicateSymbolsForInvariantTest {
        type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

        fn symbols(&self, _source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
            let first = LocalSymbol::Item {
                name: Ident::new("dup").expect("valid identifier"),
                resolved: SymbolResolution::Local(Span::unknown(ItemIndex::new(0))),
            };
            let second = LocalSymbol::Item {
                name: Ident::new("dup").expect("valid identifier"),
                resolved: SymbolResolution::Local(Span::unknown(ItemIndex::new(1))),
            };
            alloc::vec![first, second].into_iter()
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "duplicate symbol 'dup' reached local resolver construction")]
    fn local_symbol_table_rejects_duplicate_symbols() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let _table = LocalSymbolTable::new(DuplicateSymbolsForInvariantTest, source_manager);
    }

    #[test]
    fn local_symbol_table_duplicate_symbols_have_explicit_behavior() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let result = catch_unwind(AssertUnwindSafe(|| {
            LocalSymbolTable::new(DuplicateSymbolsForInvariantTest, source_manager)
        }));

        if cfg!(debug_assertions) {
            assert!(
                result.is_err(),
                "debug builds should panic when duplicates reach local resolver construction"
            );
        } else {
            let table = result
                .expect("release builds should not panic on duplicate symbols")
                .expect("release builds should still construct a table");
            let resolved = table
                .get(Span::unknown("dup"))
                .expect("release behavior should keep a deterministic symbol mapping");
            match resolved {
                SymbolResolution::Local(id) => assert_eq!(id.into_inner(), ItemIndex::new(0)),
                other => panic!("expected local symbol resolution, got {other:?}"),
            }
        }
    }
}
