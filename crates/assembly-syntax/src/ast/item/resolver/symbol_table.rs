use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_debug_types::{SourceManager, SourceSpan, Span, Spanned};

use super::{SymbolResolution, SymbolResolutionError};
use crate::{
    Path,
    ast::{AliasTarget, Ident, ItemIndex},
};

/// Maximum number of alias expansion steps permitted during symbol resolution.
///
/// This limit is intended to prevent stack overflows from maliciously deep or cyclic
/// alias graphs while remaining far above normal usage patterns.
const MAX_ALIAS_EXPANSION_DEPTH: usize = 128;

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

impl SymbolTable for &crate::library::ModuleInfo {
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

    fn checked_symbols(
        &self,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self::SymbolIter, SymbolResolutionError> {
        if self.items.len() > ItemIndex::MAX_ITEMS {
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
        let mut expansion_stack = Vec::new();
        Self::expand_with_guard(get_import, path, source_manager, &mut expansion_stack)
    }

    fn expand_with_guard<F>(
        get_import: F,
        path: Span<&Path>,
        source_manager: &dyn SourceManager,
        expansion_stack: &mut Vec<Arc<Path>>,
    ) -> Result<SymbolResolution, SymbolResolutionError>
    where
        F: Fn(&str) -> Option<AliasTarget>,
    {
        if expansion_stack.len() > MAX_ALIAS_EXPANSION_DEPTH {
            return Err(SymbolResolutionError::alias_expansion_depth_exceeded(
                path.span(),
                MAX_ALIAS_EXPANSION_DEPTH,
                source_manager,
            ));
        }

        let path_ref: &Path = *path;
        if expansion_stack.iter().any(|entry| entry.as_ref() == path_ref) {
            return Err(SymbolResolutionError::alias_expansion_cycle(path.span(), source_manager));
        }

        expansion_stack.push(Arc::from(path_ref));

        let result = {
            let (module_name, rest) = path.split_first().unwrap();
            if let Some(target) = get_import(module_name) {
                match target {
                    AliasTarget::MastRoot(digest) if rest.is_empty() => {
                        Ok(SymbolResolution::MastRoot(digest))
                    },
                    AliasTarget::MastRoot(digest) => {
                        Err(SymbolResolutionError::invalid_alias_target(
                            digest.span(),
                            path.span(),
                            source_manager,
                        ))
                    },
                    // If we have an import like `use lib::lib`, we cannot refer to the base `lib`
                    // any longer, as it has been shadowed; any attempt to
                    // further expand the path will recurse infinitely.
                    //
                    // For now, we handle this by simply stopping further expansion. In the future,
                    // we may want to refine module.get_import to allow passing
                    // an exclusion list, so that we can avoid recursing on the
                    // same import in an infinite loop.
                    AliasTarget::Path(shadowed) if shadowed.as_deref() == path => {
                        Ok(SymbolResolution::External(shadowed))
                    },
                    AliasTarget::Path(path) => {
                        let resolved = Self::expand_with_guard(
                            get_import,
                            path.as_deref(),
                            source_manager,
                            expansion_stack,
                        )?;
                        match resolved {
                            SymbolResolution::Module { id, path } => {
                                // We can consider this path fully-resolved, and mark it absolute,
                                // if it is not already
                                if rest.is_empty() {
                                    Ok(SymbolResolution::Module { id, path })
                                } else {
                                    Ok(SymbolResolution::External(
                                        path.map(|p| p.join(rest).into()),
                                    ))
                                }
                            },
                            SymbolResolution::External(resolved) => {
                                // We can consider this path fully-resolved, and mark it absolute,
                                // if it is not already
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
                // We can consider this path fully-resolved, and mark it absolute, if it is not
                // already
                Ok(SymbolResolution::External(path.map(|p| p.to_absolute().into_owned().into())))
            }
        };

        expansion_stack.pop();
        result
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        sync::Arc,
    };
    use core::str::FromStr;

    use miden_debug_types::DefaultSourceManager;

    use super::*;
    use crate::PathBuf;

    fn path_arc(path: &str) -> Arc<Path> {
        let path = PathBuf::from_str(path).expect("valid path");
        Arc::from(path.as_path())
    }

    #[test]
    fn alias_expansion_detects_cycle() {
        let source_manager = DefaultSourceManager::default();
        let mut imports = BTreeMap::<String, AliasTarget>::new();
        imports.insert("a".to_string(), AliasTarget::Path(Span::unknown(path_arc("b"))));
        imports.insert("b".to_string(), AliasTarget::Path(Span::unknown(path_arc("a"))));

        let path = PathBuf::from_str("a").expect("valid path");
        let result = LocalSymbolTable::expand(
            |name| imports.get(name).cloned(),
            Span::unknown(path.as_path()),
            &source_manager,
        );

        assert!(matches!(result, Err(SymbolResolutionError::AliasExpansionCycle { .. })));
    }

    #[test]
    fn alias_expansion_depth_boundary() {
        let source_manager = DefaultSourceManager::default();
        let mut imports = BTreeMap::<String, AliasTarget>::new();
        let max_depth = MAX_ALIAS_EXPANSION_DEPTH;
        for i in 0..max_depth {
            let current = format!("a{i}");
            let next = format!("a{}", i + 1);
            imports.insert(current, AliasTarget::Path(Span::unknown(path_arc(&next))));
        }

        let path = PathBuf::from_str("a0").expect("valid path");
        let result = LocalSymbolTable::expand(
            |name| imports.get(name).cloned(),
            Span::unknown(path.as_path()),
            &source_manager,
        )
        .expect("expected depth boundary to resolve");

        match result {
            SymbolResolution::External(resolved) => {
                let expected = format!("a{max_depth}");
                let expected = PathBuf::from_str(&expected).expect("valid path");
                let expected = expected.as_path().to_absolute().into_owned();
                assert_eq!(resolved.as_deref(), expected.as_path());
            },
            other => panic!("expected external resolution, got {other:?}"),
        }
    }

    #[test]
    fn alias_expansion_depth_exceeded() {
        let source_manager = DefaultSourceManager::default();
        let mut imports = BTreeMap::<String, AliasTarget>::new();
        for i in 0..=MAX_ALIAS_EXPANSION_DEPTH {
            let current = format!("a{i}");
            let next = format!("a{}", i + 1);
            imports.insert(current, AliasTarget::Path(Span::unknown(path_arc(&next))));
        }

        let path = PathBuf::from_str("a0").expect("valid path");
        let result = LocalSymbolTable::expand(
            |name| imports.get(name).cloned(),
            Span::unknown(path.as_path()),
            &source_manager,
        );

        assert!(matches!(
            result,
            Err(SymbolResolutionError::AliasExpansionDepthExceeded { max_depth, .. })
                if max_depth == MAX_ALIAS_EXPANSION_DEPTH
        ));
    }

    #[test]
    fn alias_expansion_handles_shadowed_import() {
        let source_manager = DefaultSourceManager::default();
        let mut imports = BTreeMap::<String, AliasTarget>::new();
        imports.insert("lib".to_string(), AliasTarget::Path(Span::unknown(path_arc("lib"))));

        let path = PathBuf::from_str("lib").expect("valid path");
        let result = LocalSymbolTable::expand(
            |name| imports.get(name).cloned(),
            Span::unknown(path.as_path()),
            &source_manager,
        )
        .expect("shadowed import should resolve");

        match result {
            SymbolResolution::External(resolved) => {
                assert_eq!(resolved.as_deref(), path.as_path());
            },
            other => panic!("expected external resolution, got {other:?}"),
        }
    }

    #[test]
    fn checked_symbols_rejects_oversized_module() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut module =
            crate::ast::Module::new(crate::ast::ModuleKind::Library, crate::Path::new("::m::huge"));

        for i in 0..=ItemIndex::MAX_ITEMS {
            module.items.push(crate::ast::Export::Constant(crate::ast::Constant::new(
                SourceSpan::UNKNOWN,
                crate::ast::Visibility::Private,
                crate::ast::Ident::new(format!("A{i}")).expect("valid identifier"),
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
                name: crate::ast::Ident::new("dup").expect("valid identifier"),
                resolved: SymbolResolution::Local(Span::unknown(ItemIndex::new(0))),
            };
            let second = LocalSymbol::Item {
                name: crate::ast::Ident::new("dup").expect("valid identifier"),
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
