use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{cell::Cell, ops::Index};

use miden_assembly_syntax::{
    Path,
    ast::{
        self, AliasTarget, ItemIndex, LocalSymbol, LocalSymbolResolver, ModuleIndex, ModuleKind,
        SymbolResolution, SymbolResolutionError, SymbolTable,
    },
    debuginfo::{SourceManager, Span, Spanned},
};

use super::{AdviceMap, LinkStatus, Symbol, SymbolItem, SymbolResolver};

/// The source from which a [LinkModule] was derived.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ModuleSource {
    /// The module was parsed from Miden Assembly source code
    Ast,
    /// The module was loaded from a Miden package's MAST forest
    Mast,
}

/// A [LinkModule] represents a module that is being linked or linked against by the linker.
///
/// Modules serve two main purposes during linking:
///
/// 1. They provide zero or more items/symbols to link and/or link against.
/// 2. They provide the context needed for resolving symbol references to concrete definitions
#[derive(Clone)]
pub struct LinkModule {
    /// The unique identifier/index assigned to this module in the containing linker instance.
    id: ModuleIndex,
    /// The kind of module being linked, i.e. kernel, executable or library.
    kind: ModuleKind,
    /// The link status of this module, i.e. whether it is unlinked, partially, or fully linked
    status: Cell<LinkStatus>,
    /// The source of the module info, i.e. parsed from MASM source code, or loaded as MAST.
    ///
    /// Whether a module is in source form or assembled form determines whether the assembler needs
    /// to perform additional processing on it or not.
    source: ModuleSource,
    /// The fully-qualified path used to refer to this module, e.g. `::std::math::u64`
    path: Arc<Path>,
    /// The set of symbols defined in this module.
    ///
    /// For modules loaded from MAST, only exported symbols will be available here.
    symbols: Vec<Symbol>,
    /// An optional [AdviceMap] to merge into the advice data of the assembled artifact.
    ///
    /// This is only relevant for modules parsed from MASM sources.
    advice_map: Option<AdviceMap>,
}

impl LinkModule {
    /// Create a new, empty [LinkModule] with the provided metadata.
    pub fn new(
        id: ModuleIndex,
        kind: ModuleKind,
        status: LinkStatus,
        source: ModuleSource,
        path: Arc<Path>,
    ) -> Self {
        Self {
            id,
            kind,
            status: Cell::new(status),
            source,
            path,
            symbols: Vec::default(),
            advice_map: None,
        }
    }

    /// Load the symbols defined by this module.
    ///
    /// Note that for modules parsed from MASM sources, this must contain _all_ symbols defined in
    /// the source module.
    #[inline]
    pub fn with_symbols(mut self, symbols: Vec<Symbol>) -> Self {
        self.symbols = symbols;
        self
    }

    /// Specify the advice map data associated with this module.
    ///
    /// The provided map will be merged into the advice data of the assembled artifact.
    #[inline]
    pub fn with_advice_map(mut self, advice_map: AdviceMap) -> Self {
        self.advice_map = Some(advice_map);
        self
    }

    /// Get the unique identifier/index of this module in the containing linker.
    #[inline(always)]
    pub fn id(&self) -> ModuleIndex {
        self.id
    }

    /// Get the current link status of this module.
    #[inline(always)]
    pub fn status(&self) -> LinkStatus {
        self.status.get()
    }

    /// Set the link status of this module.
    #[inline]
    pub fn set_status(&self, status: LinkStatus) {
        self.status.set(status);
    }

    /// Returns true if this module has not yet been visited by the linker.
    #[inline]
    pub fn is_unlinked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Unlinked)
    }

    /// Returns true if this module is fully linked.
    #[inline]
    pub fn is_linked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Linked)
    }

    /// Returns true if this module was loaded from MAST, rather than parsed from MASM sources.
    #[inline]
    pub fn is_mast(&self) -> bool {
        matches!(self.source, ModuleSource::Mast)
    }

    /// Get the source type of this module.
    #[inline(always)]
    pub fn source(&self) -> ModuleSource {
        self.source
    }

    /// Get the kind of this module, i.e. kernel, executable, or library.
    #[inline(always)]
    pub fn kind(&self) -> ModuleKind {
        self.kind
    }

    /// Set this module's kind.
    #[inline]
    pub fn set_kind(&mut self, kind: ModuleKind) {
        self.kind = kind;
    }

    /// Get the fully-qualified path of this module, e.g. `std::math::u64`
    #[inline(always)]
    pub fn path(&self) -> &Arc<Path> {
        &self.path
    }

    /// Get a reference to the optional advice map data of this module.
    #[inline]
    pub fn advice_map(&self) -> Option<&AdviceMap> {
        self.advice_map.as_ref()
    }

    /// Get an iterator over the symbols in this module.
    #[inline]
    pub fn symbols(&self) -> core::slice::Iter<'_, Symbol> {
        self.symbols.iter()
    }

    /// Get the number of symbols defined in this module.
    #[inline(always)]
    pub fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    /// Find the [Symbol] named `name` in this module
    pub fn get(&self, name: impl AsRef<str>) -> Option<&Symbol> {
        let name = name.as_ref();
        self.symbols.iter().find(|symbol| symbol.name().as_str() == name)
    }

    /// Resolve `name` relative to this module, using `resolver` for externally-defined symbols.
    pub fn resolve(
        &self,
        name: Span<&str>,
        resolver: &SymbolResolver<'_>,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let container = LinkModuleIter { resolver, module: self };
        let local_resolver = LocalSymbolResolver::new(container, resolver.source_manager_arc());
        local_resolver.resolve(name).map_err(Box::new)
    }

    /// Resolve `path` relative to this module, using `resolver` for externally-defined symbols.
    pub fn resolve_path(
        &self,
        path: Span<&Path>,
        resolver: &SymbolResolver<'_>,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let container = LinkModuleIter { resolver, module: self };
        let local_resolver = LocalSymbolResolver::new(container, resolver.source_manager_arc());
        local_resolver.resolve_path(path).map_err(Box::new)
    }
}

impl Index<ItemIndex> for LinkModule {
    type Output = Symbol;

    #[inline(always)]
    fn index(&self, index: ItemIndex) -> &Self::Output {
        &self.symbols[index.as_usize()]
    }
}

struct LinkModuleIter<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
    module: &'a LinkModule,
}

impl<'a, 'b: 'a> SymbolTable for LinkModuleIter<'a, 'b> {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        let symbols = self
            .module
            .symbols
            .iter()
            .enumerate()
            .map(|(i, symbol)| {
                let index = ItemIndex::new(i);
                let gid = self.module.id + index;
                match symbol.item() {
                    SymbolItem::Compiled(_)
                    | SymbolItem::Procedure(_)
                    | SymbolItem::Constant(_)
                    | SymbolItem::Type(_) => {
                        let path = self.module.path.join(symbol.name());
                        ast::LocalSymbol::Item {
                            name: symbol.name().clone(),
                            resolved: SymbolResolution::Exact {
                                gid,
                                path: Span::new(symbol.name().span(), path.into()),
                            },
                        }
                    },
                    SymbolItem::Alias { alias, resolved } => {
                        let name = alias.name().clone();
                        let name = Span::new(name.span(), name.into_inner());
                        if let Some(resolved) = resolved.get() {
                            let path = self.resolver.item_path(gid);
                            let span = name.span();
                            ast::LocalSymbol::Import {
                                name,
                                resolution: Ok(SymbolResolution::Exact {
                                    gid: resolved,
                                    path: Span::new(span, path),
                                }),
                            }
                        } else {
                            match alias.target() {
                                AliasTarget::MastRoot(root) => ast::LocalSymbol::Import {
                                    name,
                                    resolution: Ok(SymbolResolution::MastRoot(*root)),
                                },
                                AliasTarget::Path(path) => {
                                    let resolution = LocalSymbolResolver::expand(
                                        |name| {
                                            self.module.get(name).and_then(|sym| match sym.item() {
                                                SymbolItem::Alias { alias, .. } => {
                                                    Some(alias.target().clone())
                                                },
                                                _ => None,
                                            })
                                        },
                                        path.as_deref(),
                                        &source_manager,
                                    );
                                    ast::LocalSymbol::Import { name, resolution }
                                },
                            }
                        }
                    },
                }
            })
            .collect::<Vec<_>>();
        symbols.into_iter()
    }
}
