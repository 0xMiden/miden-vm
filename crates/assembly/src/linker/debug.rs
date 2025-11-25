use core::fmt;

use super::*;

impl fmt::Debug for Linker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linker")
            .field("nodes", &DisplayModuleGraphNodes(&self.modules))
            .field("graph", &DisplayModuleGraph(self))
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraph<'a>(&'a Linker);

impl fmt::Debug for DisplayModuleGraph<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_set()
            .entries(self.0.modules.iter().enumerate().flat_map(|(module_index, m)| {
                let module_index = ModuleIndex::new(module_index);
                (0..m.num_symbols())
                    .map(|i| {
                        let gid = module_index + ItemIndex::new(i);
                        let out_edges = self.0.callgraph.out_edges(gid);
                        Some(DisplayModuleGraphNodeWithEdges { gid, out_edges })
                    })
                    .collect::<Vec<_>>()
            }))
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraphNodes<'a>(&'a [LinkModule]);

impl fmt::Debug for DisplayModuleGraphNodes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().enumerate().flat_map(|(module_index, m)| {
                let module_index = ModuleIndex::new(module_index);

                m.symbols()
                    .enumerate()
                    .map(|(i, symbol)| DisplayModuleGraphNode {
                        id: module_index + ItemIndex::new(i),
                        path: m.path(),
                        name: symbol.name(),
                        source: m.source(),
                    })
                    .collect::<Vec<_>>()
            }))
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraphNode<'a> {
    id: GlobalItemIndex,
    path: &'a Path,
    name: &'a ast::Ident,
    source: ModuleSource,
}

impl fmt::Debug for DisplayModuleGraphNode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &format_args!("{}", &self.id))
            .field("module", &self.path)
            .field("name", &self.name)
            .field("source", &self.source)
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraphNodeWithEdges<'a> {
    gid: GlobalItemIndex,
    out_edges: &'a [GlobalItemIndex],
}

impl fmt::Debug for DisplayModuleGraphNodeWithEdges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Edge")
            .field(
                "caller",
                &format_args!("{}:{}", self.gid.module.as_usize(), self.gid.index.as_usize()),
            )
            .field(
                "callees",
                &self
                    .out_edges
                    .iter()
                    .map(|gid| format!("{}:{}", gid.module.as_usize(), gid.index.as_usize()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}
