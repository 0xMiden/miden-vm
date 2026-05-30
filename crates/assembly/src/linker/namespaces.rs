// This module is being introduced ahead of the resolver rewrite. Some lookup APIs and definition
// records are intentionally staged here before all link-time symbol queries are moved onto them.
#![allow(dead_code)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    Path,
    ast::{
        AliasTarget, GlobalItemIndex, ItemIndex, ModuleIndex, SymbolResolutionError, Visibility,
    },
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
    diagnostics::RelatedLabel,
    module::ItemInfo,
};

use super::{Linker, LinkerError, ModuleSource, SymbolItem};

/// A graph of modules, concrete items, submodule declarations, and imports known to the linker.
///
/// This is intentionally narrower than the full linker graph: it answers namespace questions only,
/// and does not know about package linkage, MAST forests, call graph state, or AST rewrites.
#[derive(Debug, Clone)]
pub struct NamespaceGraph {
    modules: Vec<ModuleNode>,
    modules_by_path: BTreeMap<Arc<Path>, ModuleIndex>,
}

/// A module in the linker namespace graph.
#[derive(Debug, Clone)]
pub struct ModuleNode {
    id: ModuleIndex,
    path: Arc<Path>,
    source: ModuleSource,
    parent: Option<ModuleIndex>,
    items: BTreeMap<String, ItemDef>,
    submodules: BTreeMap<String, ModuleEdge>,
    imports: BTreeMap<String, UseDecl>,
}

/// A declared child module edge.
#[derive(Debug, Clone)]
pub struct ModuleEdge {
    name: String,
    child: ModuleIndex,
    visibility: Visibility,
    span: SourceSpan,
}

/// A concrete item definition.
#[derive(Debug, Clone)]
pub struct ItemDef {
    id: GlobalItemIndex,
    kind: ItemKind,
    visibility: Visibility,
    span: SourceSpan,
}

/// The kind of item stored in a namespace graph node.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ItemKind {
    Procedure,
    Constant,
    Type,
}

/// An import declaration.
#[derive(Debug, Clone)]
pub struct UseDecl {
    owner: ModuleIndex,
    alias: String,
    visibility: Visibility,
    target: AliasTarget,
    span: SourceSpan,
}

/// The result of resolving an import target.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResolvedUse {
    Module(ModuleIndex),
    Item(GlobalItemIndex),
}

/// Import resolutions keyed by the module that owns the import and the local alias name.
#[derive(Debug, Default, Clone)]
pub struct ResolvedImports {
    imports: BTreeMap<(ModuleIndex, String), ResolvedUse>,
}

impl ResolvedImports {
    #[inline]
    pub fn get(&self, owner: ModuleIndex, alias: &str) -> Option<ResolvedUse> {
        self.imports.get(&(owner, alias.to_string())).copied()
    }
}

impl NamespaceGraph {
    /// Build a namespace graph from the modules currently registered in `linker`.
    pub fn build(linker: &Linker) -> Result<Self, LinkerError> {
        let mut modules_by_path = BTreeMap::new();

        for module in linker.modules.iter() {
            if modules_by_path.insert(module.path().clone(), module.id()).is_some() {
                return Err(LinkerError::DuplicateModule { path: module.path().clone() });
            }
        }

        let mut graph = Self {
            modules: linker
                .modules
                .iter()
                .map(|module| ModuleNode::from_link_module(module, linker))
                .collect::<Result<Vec<_>, _>>()?,
            modules_by_path,
        };
        graph.connect_submodule_edges(linker)?;
        graph.validate_source_module_declarations()?;
        Ok(graph)
    }

    /// Find a module by exact path.
    #[inline]
    pub fn find_module_index(&self, path: &Path) -> Option<ModuleIndex> {
        self.modules_by_path.get(path).copied()
    }

    /// Get a module node by id.
    #[inline]
    pub fn module(&self, id: ModuleIndex) -> &ModuleNode {
        &self.modules[id.as_usize()]
    }

    #[cfg(test)]
    fn num_modules(&self) -> usize {
        self.modules.len()
    }

    /// Return every module reachable from `root` by following public submodule declarations.
    pub fn reachable_from_root(&self, root: ModuleIndex) -> Vec<ModuleIndex> {
        let mut reachable = BTreeSet::new();
        let mut stack = vec![root];

        while let Some(module_index) = stack.pop() {
            if !reachable.insert(module_index) {
                continue;
            }

            for edge in self.module(module_index).submodules.values() {
                if edge.visibility.is_public() {
                    stack.push(edge.child);
                }
            }
        }

        reachable.into_iter().collect()
    }

    /// Resolve all path imports without consulting any imports from the importing module.
    pub fn resolve_imports(&self, linker: &Linker) -> Result<ResolvedImports, LinkerError> {
        let mut imports = ResolvedImports::default();

        for module in self.modules.iter() {
            for import in module.imports.values() {
                let AliasTarget::Path(path) = import.target() else {
                    continue;
                };
                let resolved =
                    self.resolve_import_target(import.owner(), path.as_deref(), linker)?;

                if import.visibility().is_public()
                    && let ResolvedUse::Module(id) = resolved
                {
                    return Err(LinkerError::ModuleReExport {
                        span: import.span(),
                        source_file: source_file(linker.source_manager.as_ref(), import.span()),
                        path: self.module(id).path.clone(),
                    });
                }

                imports.imports.insert((import.owner(), import.alias().to_string()), resolved);
            }
        }

        Ok(imports)
    }

    fn resolve_import_target(
        &self,
        owner: ModuleIndex,
        path: Span<&Path>,
        linker: &Linker,
    ) -> Result<ResolvedUse, LinkerError> {
        let Some((first, rest)) = path.split_first() else {
            return Err(undefined_symbol(linker, path));
        };

        if first == "self" {
            if rest.is_empty() {
                return Err(undefined_symbol(linker, path));
            }
            return self.resolve_self_relative_path(owner, rest, path.span(), linker);
        }

        match self.resolve_global_path(owner, path.into_inner(), path.span(), None, linker) {
            Ok(resolved) => Ok(resolved),
            Err(LinkerError::UndefinedSymbol { .. }) => {
                let owner_module = self.module(owner);
                if owner_module.import(first).is_some() {
                    Err(LinkerError::ImportTargetUsesImport {
                        span: path.span(),
                        source_file: source_file(linker.source_manager.as_ref(), path.span()),
                        path: path.into_inner().to_path_buf().into_boxed_path().into(),
                        alias: first.to_string(),
                    })
                } else {
                    Err(undefined_symbol(linker, path))
                }
            },
            Err(err) => Err(err),
        }
    }

    /// Resolve a path referenced from code in `owner`.
    ///
    /// Unlike import declarations, code references may start with a local import alias. Imports are
    /// still not expanded recursively here; this only consults the already-resolved import table.
    pub fn resolve_code_path(
        &self,
        owner: ModuleIndex,
        path: Span<&Path>,
        imports: &ResolvedImports,
        linker: &Linker,
    ) -> Result<ResolvedUse, LinkerError> {
        if path.is_absolute() {
            return self.resolve_global_path(
                owner,
                path.into_inner(),
                path.span(),
                Some(imports),
                linker,
            );
        }

        let Some((first, rest)) = path.split_first() else {
            return Err(undefined_symbol(linker, path));
        };

        if first == "self" {
            if rest.is_empty() {
                return Err(undefined_symbol(linker, path));
            }
            return self.resolve_self_relative_path(owner, rest, path.span(), linker);
        }

        let owner_module = self.module(owner);
        if rest.is_empty() {
            if let Some(item) = owner_module.item(first) {
                self.ensure_item_visible(owner, item, path.span(), linker)?;
                return Ok(ResolvedUse::Item(item.id()));
            }

            if let Some(resolved) = imports.get(owner, first) {
                return Ok(resolved);
            }
        } else {
            if let Some(item) = owner_module.item(first) {
                return Err(SymbolResolutionError::invalid_sub_path(
                    path.span(),
                    item.span(),
                    linker.source_manager.as_ref(),
                )
                .into());
            }

            if let Some(resolved) = imports.get(owner, first) {
                return match resolved {
                    ResolvedUse::Module(module) => {
                        self.resolve_path_from_module(owner, module, rest, path.span(), linker)
                    },
                    ResolvedUse::Item(item) => Err(SymbolResolutionError::invalid_sub_path(
                        path.span(),
                        linker[item.module][item.index].name().span(),
                        linker.source_manager.as_ref(),
                    )
                    .into()),
                };
            }
        }

        self.resolve_global_path(owner, path.into_inner(), path.span(), Some(imports), linker)
    }

    fn resolve_self_relative_path(
        &self,
        owner: ModuleIndex,
        path: &Path,
        span: SourceSpan,
        linker: &Linker,
    ) -> Result<ResolvedUse, LinkerError> {
        let mut current = owner;
        let mut remaining = path;

        loop {
            let Some((component, rest)) = remaining.split_first() else {
                return Err(undefined_symbol_from_path(linker, span, path));
            };
            let module = self.module(current);

            if rest.is_empty() {
                if let Some(edge) = module.submodule(component) {
                    self.ensure_submodule_visible(edge, span, linker)?;
                    return Ok(ResolvedUse::Module(edge.child()));
                }

                if let Some(item) = module.item(component) {
                    self.ensure_item_visible(owner, item, span, linker)?;
                    return Ok(ResolvedUse::Item(item.id()));
                }

                return Err(undefined_symbol_from_path(linker, span, path));
            }

            if let Some(edge) = module.submodule(component) {
                self.ensure_submodule_visible(edge, span, linker)?;
                current = edge.child();
                remaining = rest;
                continue;
            }

            if let Some(item) = module.item(component) {
                return Err(SymbolResolutionError::invalid_sub_path(
                    span,
                    item.span(),
                    linker.source_manager.as_ref(),
                )
                .into());
            }

            return Err(undefined_symbol_from_path(linker, span, path));
        }
    }

    fn resolve_path_from_module(
        &self,
        owner: ModuleIndex,
        module: ModuleIndex,
        path: &Path,
        span: SourceSpan,
        linker: &Linker,
    ) -> Result<ResolvedUse, LinkerError> {
        let mut current = module;
        let mut remaining = path;

        loop {
            let Some((component, rest)) = remaining.split_first() else {
                return Ok(ResolvedUse::Module(current));
            };
            let module = self.module(current);

            if rest.is_empty() {
                if let Some(item) = module.item(component) {
                    self.ensure_item_visible(owner, item, span, linker)?;
                    return Ok(ResolvedUse::Item(item.id()));
                }

                if let Some(edge) = module.submodule(component) {
                    self.ensure_submodule_visible(edge, span, linker)?;
                    return Ok(ResolvedUse::Module(edge.child()));
                }

                return Err(undefined_symbol_from_path(linker, span, path));
            }

            if let Some(edge) = module.submodule(component) {
                self.ensure_submodule_visible(edge, span, linker)?;
                current = edge.child();
                remaining = rest;
                continue;
            }

            if let Some(item) = module.item(component) {
                return Err(SymbolResolutionError::invalid_sub_path(
                    span,
                    item.span(),
                    linker.source_manager.as_ref(),
                )
                .into());
            }

            return Err(undefined_symbol_from_path(linker, span, path));
        }
    }

    fn resolve_global_path(
        &self,
        owner: ModuleIndex,
        path: &Path,
        span: SourceSpan,
        imports: Option<&ResolvedImports>,
        linker: &Linker,
    ) -> Result<ResolvedUse, LinkerError> {
        if let Some(module) = self.find_global_module_index(path) {
            self.ensure_module_visible(module, span, linker)?;
            return Ok(ResolvedUse::Module(module));
        }

        let Some((name, parent_path)) = path.split_last() else {
            return Err(undefined_symbol_from_path(linker, span, path));
        };

        if parent_path.is_empty() && !parent_path.is_absolute() {
            return Err(undefined_symbol_from_path(linker, span, path));
        }

        let Some(parent) = self.find_global_module_index(parent_path) else {
            return Err(undefined_symbol_from_path(linker, span, path));
        };
        self.ensure_module_visible(parent, span, linker)?;
        let module = self.module(parent);

        if let Some(item) = module.item(name) {
            self.ensure_item_visible(owner, item, span, linker)?;
            return Ok(ResolvedUse::Item(item.id()));
        }

        if let Some(edge) = module.submodule(name) {
            self.ensure_submodule_visible(edge, span, linker)?;
            return Ok(ResolvedUse::Module(edge.child()));
        }

        if let Some(imports) = imports
            && let Some(import) = module.import(name)
            && import.visibility().is_public()
            && let Some(resolved) = imports.get(parent, name)
        {
            return Ok(resolved);
        }

        Err(undefined_symbol_from_path(linker, span, path))
    }

    fn find_global_module_index(&self, path: &Path) -> Option<ModuleIndex> {
        self.find_module_index(path)
            .or_else(|| {
                path.is_absolute().then(|| self.find_module_index(path.to_relative())).flatten()
            })
            .or_else(|| {
                if path.is_absolute() {
                    None
                } else {
                    path.to_absolute()
                        .ok()
                        .and_then(|absolute| self.find_module_index(absolute.as_ref()))
                }
            })
    }

    fn ensure_module_visible(
        &self,
        module: ModuleIndex,
        span: SourceSpan,
        linker: &Linker,
    ) -> Result<(), LinkerError> {
        let mut child = module;
        while let Some(parent) = self.module(child).parent() {
            let edge = self
                .module(parent)
                .submodules
                .values()
                .find(|edge| edge.child == child)
                .expect("child parent edge must exist");
            self.ensure_submodule_visible(edge, span, linker)?;
            child = parent;
        }

        Ok(())
    }

    fn ensure_submodule_visible(
        &self,
        edge: &ModuleEdge,
        span: SourceSpan,
        linker: &Linker,
    ) -> Result<(), LinkerError> {
        if edge.visibility().is_public() {
            return Ok(());
        }

        let child = self.module(edge.child());
        let defined_source_file = source_file(linker.source_manager.as_ref(), edge.span());
        let source_file = source_file(linker.source_manager.as_ref(), span);
        Err(LinkerError::PrivateSubmodule {
            span,
            source_file,
            module: child.path.clone(),
            defined: Some(
                RelatedLabel::advice("the referenced submodule is private")
                    .with_labeled_span(edge.span(), "the referenced submodule is private")
                    .with_source_file(defined_source_file),
            ),
        })
    }

    fn ensure_item_visible(
        &self,
        owner: ModuleIndex,
        item: &ItemDef,
        span: SourceSpan,
        linker: &Linker,
    ) -> Result<(), LinkerError> {
        if owner == item.id().module || item.visibility().is_public() {
            return Ok(());
        }

        Err(SymbolResolutionError::private_symbol(
            span,
            item.span(),
            linker.source_manager.as_ref(),
        )
        .into())
    }

    fn connect_submodule_edges(&mut self, linker: &Linker) -> Result<(), LinkerError> {
        for parent in linker.modules.iter() {
            let parent_id = parent.id();
            for decl in parent.submodules() {
                let name = decl.name.as_str();
                if self.modules[parent_id.as_usize()].contains_member(name) {
                    return Err(name_conflict(linker, parent, name, decl.name.span(), "submodule"));
                }

                let child_path = parent.path().join(&decl.name);
                let child = self.find_module_index(child_path.as_path()).ok_or_else(|| {
                    LinkerError::UndefinedModule {
                        span: decl.name.span(),
                        source_file: source_file(linker.source_manager.as_ref(), decl.name.span()),
                        path: child_path.into_boxed_path().into(),
                    }
                })?;

                let edge = ModuleEdge {
                    name: name.to_string(),
                    child,
                    visibility: decl.visibility,
                    span: decl.name.span(),
                };
                self.modules[parent_id.as_usize()].submodules.insert(edge.name.clone(), edge);

                let child_node = &mut self.modules[child.as_usize()];
                child_node.parent.get_or_insert(parent_id);
            }
        }

        Ok(())
    }

    fn validate_source_module_declarations(&self) -> Result<(), LinkerError> {
        for module in self.modules.iter().filter(|module| module.source == ModuleSource::Ast) {
            let Some((name, parent_path)) = module.path.split_last() else {
                continue;
            };

            if parent_path.is_empty() {
                continue;
            }

            let Some(parent_id) = self.find_module_index(parent_path) else {
                continue;
            };
            let parent = self.module(parent_id);

            match parent.submodule(name) {
                Some(edge) if edge.child == module.id => (),
                _ => {
                    return Err(LinkerError::UndeclaredSubmodule {
                        path: module.path.clone(),
                        parent: parent.path.clone(),
                        name: name.to_string(),
                    });
                },
            }
        }

        Ok(())
    }
}

impl ModuleNode {
    fn from_link_module(module: &super::LinkModule, linker: &Linker) -> Result<Self, LinkerError> {
        let mut node = Self {
            id: module.id(),
            path: module.path().clone(),
            source: module.source(),
            parent: None,
            items: BTreeMap::default(),
            submodules: BTreeMap::default(),
            imports: BTreeMap::default(),
        };

        for (index, symbol) in module.symbols().enumerate() {
            let name = symbol.name().as_str().to_string();
            let span = symbol.name().span();
            if node.contains_member(&name) {
                return Err(name_conflict(
                    linker,
                    module,
                    &name,
                    span,
                    match symbol.item() {
                        SymbolItem::Alias { .. } => "import",
                        _ => "item",
                    },
                ));
            }

            match symbol.item() {
                SymbolItem::Alias { alias, .. } => {
                    node.imports.insert(
                        name.clone(),
                        UseDecl {
                            owner: module.id(),
                            alias: name,
                            visibility: symbol.visibility(),
                            target: alias.target().clone(),
                            span: alias.span(),
                        },
                    );
                },
                item => {
                    node.items.insert(
                        name,
                        ItemDef {
                            id: module.id() + ItemIndex::new(index),
                            kind: ItemKind::from_symbol_item(item),
                            visibility: symbol.visibility(),
                            span,
                        },
                    );
                },
            }
        }

        Ok(node)
    }

    fn contains_member(&self, name: &str) -> bool {
        self.items.contains_key(name)
            || self.imports.contains_key(name)
            || self.submodules.contains_key(name)
    }

    #[inline]
    pub fn id(&self) -> ModuleIndex {
        self.id
    }

    #[inline]
    pub fn path(&self) -> &Arc<Path> {
        &self.path
    }

    #[inline]
    pub fn source(&self) -> ModuleSource {
        self.source
    }

    #[inline]
    pub fn parent(&self) -> Option<ModuleIndex> {
        self.parent
    }

    #[inline]
    pub fn item(&self, name: &str) -> Option<&ItemDef> {
        self.items.get(name)
    }

    #[inline]
    pub fn submodule(&self, name: &str) -> Option<&ModuleEdge> {
        self.submodules.get(name)
    }

    #[inline]
    pub fn import(&self, name: &str) -> Option<&UseDecl> {
        self.imports.get(name)
    }
}

impl ModuleEdge {
    #[inline]
    pub fn child(&self) -> ModuleIndex {
        self.child
    }

    #[inline]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    #[inline]
    pub fn span(&self) -> SourceSpan {
        self.span
    }
}

impl ItemDef {
    #[inline]
    pub fn id(&self) -> GlobalItemIndex {
        self.id
    }

    #[inline]
    pub fn kind(&self) -> ItemKind {
        self.kind
    }

    #[inline]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    #[inline]
    pub fn span(&self) -> SourceSpan {
        self.span
    }
}

impl UseDecl {
    #[inline]
    pub fn owner(&self) -> ModuleIndex {
        self.owner
    }

    #[inline]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    #[inline]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    #[inline]
    pub fn target(&self) -> &AliasTarget {
        &self.target
    }

    #[inline]
    pub fn span(&self) -> SourceSpan {
        self.span
    }
}

impl ItemKind {
    fn from_symbol_item(item: &SymbolItem) -> Self {
        match item {
            SymbolItem::Procedure(_) | SymbolItem::Compiled(ItemInfo::Procedure(_)) => {
                Self::Procedure
            },
            SymbolItem::Constant(_) | SymbolItem::Compiled(ItemInfo::Constant(_)) => Self::Constant,
            SymbolItem::Type(_) | SymbolItem::Compiled(ItemInfo::Type(_)) => Self::Type,
            SymbolItem::Alias { .. } => unreachable!("aliases are stored as namespace imports"),
        }
    }
}

fn name_conflict(
    linker: &Linker,
    module: &super::LinkModule,
    name: &str,
    span: SourceSpan,
    kind: &'static str,
) -> LinkerError {
    LinkerError::NamespaceNameConflict {
        span,
        source_file: source_file(linker.source_manager.as_ref(), span),
        module: module.path().clone(),
        name: name.to_string(),
        kind,
    }
}

fn undefined_symbol(linker: &Linker, path: Span<&Path>) -> LinkerError {
    undefined_symbol_from_path(linker, path.span(), path.into_inner())
}

fn undefined_symbol_from_path(linker: &Linker, span: SourceSpan, path: &Path) -> LinkerError {
    LinkerError::UndefinedSymbol {
        span,
        source_file: source_file(linker.source_manager.as_ref(), span),
        path: path.to_path_buf().into_boxed_path().into(),
    }
}

fn source_file(
    source_manager: &dyn SourceManager,
    span: SourceSpan,
) -> Option<Arc<miden_assembly_syntax::debuginfo::SourceFile>> {
    source_manager.get(span.source_id()).ok()
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, sync::Arc};

    use miden_assembly_syntax::{
        Parse, Path,
        debuginfo::{DefaultSourceManager, SourceLanguage, SourceManager, Span},
    };

    use super::*;

    fn parse_module(
        source_manager: Arc<dyn SourceManager>,
        name: &str,
        source: &str,
    ) -> Box<miden_assembly_syntax::ast::Module> {
        source_manager
            .load(SourceLanguage::Masm, name.into(), source.to_string())
            .parse(false, source_manager)
            .expect("module should parse")
    }

    #[test]
    fn namespace_graph_records_items_imports_and_public_submodule_edges() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace ::root

                pub mod child

                use external::module->external

                pub proc entry
                    push.1
                end
            "#,
        );
        let mut child = parse_module(
            source_manager.clone(),
            "child.masm",
            r#"
                namespace ::root::child

                pub const VALUE = 1
            "#,
        );

        let mut linker = Linker::new(source_manager);
        let root_id = linker.link_module(&mut root).expect("root link should succeed");
        let child_id = linker.link_module(&mut child).expect("child link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");

        assert_eq!(graph.num_modules(), 2);
        assert_eq!(graph.find_module_index(Path::new("::root")), Some(root_id));
        assert_eq!(graph.find_module_index(Path::new("::root::child")), Some(child_id));
        assert_eq!(graph.module(root_id).submodule("child").unwrap().child(), child_id);
        assert_eq!(graph.module(child_id).parent(), Some(root_id));
        assert!(graph.module(root_id).item("entry").is_some());
        assert!(graph.module(root_id).import("external").is_some());
        assert!(graph.module(child_id).item("VALUE").is_some());
    }

    #[test]
    fn namespace_graph_rejects_declared_missing_child_module() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace ::root

                pub mod missing
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut root).expect("root link should succeed");

        let err = NamespaceGraph::build(&linker).expect_err("missing child should fail");
        assert!(matches!(err, LinkerError::UndefinedModule { .. }));
    }

    #[test]
    fn namespace_graph_rejects_undeclared_child_module() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace ::root
            "#,
        );
        let mut child = parse_module(
            source_manager.clone(),
            "child.masm",
            r#"
                namespace ::root::child
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut root).expect("root link should succeed");
        linker.link_module(&mut child).expect("child link should succeed");

        let err = NamespaceGraph::build(&linker).expect_err("undeclared child should fail");
        assert!(matches!(err, LinkerError::UndeclaredSubmodule { .. }));
    }

    #[test]
    fn namespace_graph_resolves_module_and_item_imports_independently() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut imported = parse_module(
            source_manager.clone(),
            "imported.masm",
            r#"
                namespace lib::mod

                pub const VALUE = 1
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                use lib::mod
                use lib::mod::VALUE
            "#,
        );

        let mut linker = Linker::new(source_manager);
        let imported_id = linker.link_module(&mut imported).expect("imported link should succeed");
        let consumer_id = linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let imports = graph.resolve_imports(&linker).expect("imports should resolve");

        assert_eq!(imports.get(consumer_id, "mod"), Some(ResolvedUse::Module(imported_id)));
        assert!(matches!(imports.get(consumer_id, "VALUE"), Some(ResolvedUse::Item(_))));
    }

    #[test]
    fn namespace_graph_resolves_code_paths_through_imported_modules() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut imported = parse_module(
            source_manager.clone(),
            "imported.masm",
            r#"
                namespace lib::mod

                pub const VALUE = 1
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                use lib::mod
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut imported).expect("imported link should succeed");
        let consumer_id = linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let imports = graph.resolve_imports(&linker).expect("imports should resolve");
        let resolved = graph
            .resolve_code_path(
                consumer_id,
                Span::unknown(Path::new("mod::VALUE")),
                &imports,
                &linker,
            )
            .expect("code path should resolve through imported module");

        assert!(matches!(resolved, ResolvedUse::Item(_)));
    }

    #[test]
    fn namespace_graph_resolves_absolute_code_paths_globally() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut imported = parse_module(
            source_manager.clone(),
            "imported.masm",
            r#"
                namespace real::mod

                pub const VALUE = 1
            "#,
        );
        let mut global = parse_module(
            source_manager.clone(),
            "global.masm",
            r#"
                namespace lib

                pub const VALUE = 2
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                use real::mod->lib
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut imported).expect("imported link should succeed");
        let global_id = linker.link_module(&mut global).expect("global link should succeed");
        let consumer_id = linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let imports = graph.resolve_imports(&linker).expect("imports should resolve");
        let resolved = graph
            .resolve_code_path(
                consumer_id,
                Span::unknown(Path::new("::lib::VALUE")),
                &imports,
                &linker,
            )
            .expect("absolute code path should resolve globally");

        assert!(matches!(resolved, ResolvedUse::Item(gid) if gid.module == global_id));
    }

    #[test]
    fn namespace_graph_rejects_private_submodule_import() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace root

                mod child
            "#,
        );
        let mut child = parse_module(
            source_manager.clone(),
            "child.masm",
            r#"
                namespace root::child
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                use root::child
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut root).expect("root link should succeed");
        linker.link_module(&mut child).expect("child link should succeed");
        linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let err = graph.resolve_imports(&linker).expect_err("private submodule should fail");
        assert!(matches!(err, LinkerError::PrivateSubmodule { .. }));
    }

    #[test]
    fn namespace_graph_rejects_module_reexport() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace root

                pub mod child
            "#,
        );
        let mut child = parse_module(
            source_manager.clone(),
            "child.masm",
            r#"
                namespace root::child
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                pub use root::child
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut root).expect("root link should succeed");
        linker.link_module(&mut child).expect("child link should succeed");
        linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let err = graph.resolve_imports(&linker).expect_err("module re-export should fail");
        assert!(matches!(err, LinkerError::ModuleReExport { .. }));
    }

    #[test]
    fn namespace_graph_rejects_imports_through_other_imports() {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut root = parse_module(
            source_manager.clone(),
            "root.masm",
            r#"
                namespace root

                pub mod child
            "#,
        );
        let mut child = parse_module(
            source_manager.clone(),
            "child.masm",
            r#"
                namespace root::child

                pub const VALUE = 1
            "#,
        );
        let mut consumer = parse_module(
            source_manager.clone(),
            "consumer.masm",
            r#"
                namespace app

                use root::child
                use child::VALUE
            "#,
        );

        let mut linker = Linker::new(source_manager);
        linker.link_module(&mut root).expect("root link should succeed");
        linker.link_module(&mut child).expect("child link should succeed");
        linker.link_module(&mut consumer).expect("consumer link should succeed");

        let graph = NamespaceGraph::build(&linker).expect("namespace graph should build");
        let err = graph.resolve_imports(&linker).expect_err("import chaining should fail");
        assert!(matches!(err, LinkerError::ImportTargetUsesImport { .. }));
    }
}
