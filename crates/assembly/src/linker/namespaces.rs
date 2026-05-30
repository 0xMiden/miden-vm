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
    ast::{AliasTarget, GlobalItemIndex, ItemIndex, ModuleIndex, Visibility},
    debuginfo::{SourceManager, SourceSpan, Spanned},
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
        debuginfo::{DefaultSourceManager, SourceLanguage, SourceManager},
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
}
