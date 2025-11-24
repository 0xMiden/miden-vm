// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{GlobalItemIndex, ModuleIndex};
use crate::{
    Path, Word,
    ast::{AliasTarget, Ident, ItemIndex},
    diagnostics::{Diagnostic, miette},
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
    /// The name was resolved to a known definition in the same module at the given index
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

/// A lookup table for item names in the context of some module
pub struct LocalSymbolResolver {
    symbols: SymbolTable,
}

impl From<&crate::ast::Module> for LocalSymbolResolver {
    fn from(module: &crate::ast::Module) -> Self {
        Self { symbols: SymbolTable::from(module) }
    }
}

impl From<&crate::library::ModuleInfo> for LocalSymbolResolver {
    fn from(module: &crate::library::ModuleInfo) -> Self {
        Self { symbols: SymbolTable::from(module) }
    }
}

struct SymbolTable {
    symbols: BTreeMap<Arc<str>, ItemIndex>,
    imports: BTreeMap<Arc<str>, Result<SymbolResolution, LocalSymbolResolutionError>>,
    items: Vec<Symbol>,
}

#[derive(Debug)]
enum Symbol {
    Item { name: Ident, resolved: SymbolResolution },
    Import(Span<Arc<str>>),
}

#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum LocalSymbolResolutionError {
    #[error("undefined symbol reference")]
    #[diagnostic(help("maybe you are missing an import?"))]
    UndefinedSymbol {
        #[label("this symbol path could not be resolved")]
        span: SourceSpan,
    },
    #[error("invalid symbol reference")]
    #[diagnostic(help(
        "references to a subpath of an imported symbol require the imported item to be a module"
    ))]
    InvalidAliasTarget {
        #[label("this reference specifies a subpath relative to an import")]
        referer: SourceSpan,
        #[label("but the import refers to a procedure, constant, or type item")]
        span: SourceSpan,
    },
    #[error("invalid symbol path")]
    #[diagnostic(help("all ancestors of a path must be modules"))]
    InvalidSubPath {
        #[label("this path specifies a subpath relative to another item")]
        span: SourceSpan,
        #[label("but this item is not a module")]
        relative_to: SourceSpan,
    },
    #[error("invalid symbol reference: wrong type")]
    #[diagnostic()]
    InvalidSymbolType {
        expected: &'static str,
        #[label("expected this symbol to reference a {expected} item")]
        span: SourceSpan,
        #[label("but the symbol resolved to this item")]
        actual: SourceSpan,
    },
}

impl From<&crate::library::ModuleInfo> for SymbolTable {
    fn from(module: &crate::library::ModuleInfo) -> Self {
        let mut symbols = BTreeMap::default();
        let module_items = module.items();
        let mut items = Vec::with_capacity(module_items.len());

        for (index, item) in module_items {
            let name = item.name().clone();
            let span = name.span();

            symbols.insert(name.clone().into_inner(), index);
            assert_eq!(index.as_usize(), items.len());
            items.push(Symbol::Item {
                name,
                resolved: SymbolResolution::Local(Span::new(span, index)),
            });
        }

        Self {
            symbols,
            items,
            imports: Default::default(),
        }
    }
}

impl From<&crate::ast::Module> for SymbolTable {
    fn from(module: &crate::ast::Module) -> Self {
        use crate::ast::{AliasTarget, Export};

        let mut symbols = BTreeMap::default();
        let mut imports = BTreeMap::default();
        let mut items = Vec::with_capacity(module.items.len());

        for (i, item) in module.items.iter().enumerate() {
            let id = ItemIndex::new(i);
            let name = item.name().clone();
            let span = name.span();
            let name = name.into_inner();

            symbols.insert(name.clone(), id);

            if let Export::Alias(alias) = item {
                items.push(Symbol::Import(Span::new(span, name.clone())));
                match alias.target() {
                    AliasTarget::MastRoot(root) => {
                        imports.insert(name.clone(), Ok(SymbolResolution::MastRoot(*root)));
                    },
                    AliasTarget::Path(path) => {
                        let expanded = SymbolTable::expand(module, path.as_deref());
                        imports.insert(name, expanded);
                    },
                }
            } else {
                items.push(Symbol::Item {
                    name: Ident::from_raw_parts(Span::new(span, name)),
                    resolved: SymbolResolution::Local(Span::new(span, id)),
                });
            }
        }

        Self { symbols, imports, items }
    }
}

impl SymbolTable {
    /// Get the symbol `name` from this table, if present.
    ///
    /// Returns `Ok(None)` if the symbol is undefined in this table.
    ///
    /// Returns `Ok(Some)` if the symbol is defined, and we were able to resolve it to either a
    /// local or external item without encountering any issues.
    ///
    /// Returns `Err` if the symbol cannot possibly be resolved, e.g. the expanded path refers to
    /// a child of an item that cannot have children, such as a procedure.
    pub fn get(&self, name: &str) -> Result<Option<SymbolResolution>, LocalSymbolResolutionError> {
        log::debug!(target: "symbol-table", "attempting to resolve '{name}'");
        let Some(item) = self.symbols.get(name).copied() else {
            return Ok(None);
        };
        match &self.items[item.as_usize()] {
            Symbol::Item { resolved, .. } => {
                log::debug!(target: "symbol-table", "resolved '{name}' to {resolved:?}");
                Ok(Some(resolved.clone()))
            },
            Symbol::Import(name) => {
                log::debug!(target: "symbol-table", "'{name}' refers to an import");
                let found = self
                    .imports
                    .get(name.inner())
                    .unwrap_or_else(|| {
                        panic!("expected '{name}' to resolve to an import in this symbol table")
                    })
                    .clone();
                match found {
                    Ok(resolved) => {
                        log::debug!(target: "symbol-table", "resolved '{name}' to {resolved:?}");
                        Ok(Some(resolved))
                    },
                    Err(err) => {
                        log::error!(target: "symbol-table", "resolution of '{name}' failed: {err}");
                        Err(err)
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
    fn expand(
        module: &crate::ast::Module,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LocalSymbolResolutionError> {
        let (module_name, rest) = path.split_first().unwrap();
        if let Some(import) = module.get_import(module_name) {
            match import.target() {
                AliasTarget::MastRoot(digest) if rest.is_empty() => {
                    Ok(SymbolResolution::MastRoot(*digest))
                },
                AliasTarget::MastRoot(digest) => {
                    Err(LocalSymbolResolutionError::InvalidAliasTarget {
                        referer: path.span(),
                        span: digest.span(),
                    })
                },
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
                    let resolved = Self::expand(module, path.as_deref())?;
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
                            Err(LocalSymbolResolutionError::InvalidAliasTarget {
                                referer: path.span(),
                                span: digest.span(),
                            })
                        },
                        SymbolResolution::Exact { path: item_path, .. } => {
                            Err(LocalSymbolResolutionError::InvalidAliasTarget {
                                referer: path.span(),
                                span: item_path.span(),
                            })
                        },
                        SymbolResolution::Local(item) => {
                            Err(LocalSymbolResolutionError::InvalidAliasTarget {
                                referer: path.span(),
                                span: item.span(),
                            })
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

impl LocalSymbolResolver {
    /// Try to resolve `name` to an item, either local or external
    ///
    /// See `SymbolTable::get` for details.
    pub fn resolve(
        &self,
        name: &str,
    ) -> Result<Option<SymbolResolution>, LocalSymbolResolutionError> {
        self.symbols.get(name)
    }

    /// Try to resolve `path` to an item, either local or external
    pub fn resolve_path(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<SymbolResolution>, LocalSymbolResolutionError> {
        if path.is_absolute() {
            return Ok(Some(SymbolResolution::External(path.map(|p| p.into()))));
        }
        log::debug!(target: "local-symbol-resolver", "resolving path '{path}'");
        let (ns, subpath) = path.split_first().expect("invalid item path");
        log::debug!(target: "local-symbol-resolver", "resolving symbol '{ns}'");
        match self.resolve(ns)? {
            Some(SymbolResolution::External(target)) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to import of '{target}'");
                if subpath.is_empty() {
                    log::debug!(target: "local-symbol-resolver", "resolved '{path}' '{target}'");
                    Ok(Some(SymbolResolution::External(target)))
                } else {
                    let resolved = target.join(subpath).into();
                    log::debug!(target: "local-symbol-resolver", "resolved '{path}' '{resolved}'");
                    Ok(Some(SymbolResolution::External(Span::new(target.span(), resolved))))
                }
            },
            Some(SymbolResolution::Local(item)) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to local item '{item}'");
                if subpath.is_empty() {
                    return Ok(Some(SymbolResolution::Local(item)));
                }

                // This is an invalid subpath reference
                log::error!(target: "local-symbol-resolver", "cannot resolve '{subpath}' relative to non-module item");
                Err(LocalSymbolResolutionError::InvalidSubPath {
                    span: path.span(),
                    relative_to: item.span(),
                })
            },
            Some(SymbolResolution::MastRoot(digest)) => {
                log::debug!(target: "local-symbol-resolver", "resolved '{ns}' to procedure root '{digest}'");
                if subpath.is_empty() {
                    return Ok(Some(SymbolResolution::MastRoot(digest)));
                }

                // This is an invalid subpath reference
                log::error!(target: "local-symbol-resolver", "cannot resolve '{subpath}' relative to procedure");
                Err(LocalSymbolResolutionError::InvalidSubPath {
                    span: path.span(),
                    relative_to: digest.span(),
                })
            },
            Some(SymbolResolution::Module { id, path, .. }) => {
                if subpath.is_empty() {
                    Ok(Some(SymbolResolution::Module { id, path }))
                } else {
                    Ok(Some(SymbolResolution::External(path.map(|p| p.join(subpath).into()))))
                }
            },
            Some(SymbolResolution::Exact { .. }) => unreachable!(),
            None => {
                log::debug!(target: "local-symbol-resolver", "could not resolve '{ns}' locally, must refer to an external module");
                Ok(None)
            },
        }
    }

    /// Get the name of the item at `index`
    ///
    /// This is guaranteed to resolve if `index` is valid, and will panic if not.
    pub fn get_item_name(&self, index: ItemIndex) -> Ident {
        match &self.symbols.items[index.as_usize()] {
            Symbol::Item { name, .. } => name.clone(),
            Symbol::Import(name) => Ident::from_raw_parts(name.clone()),
        }
    }
}
