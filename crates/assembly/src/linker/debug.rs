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
            .entries(self.0.modules.iter().filter_map(|m| m.as_ref()).enumerate().flat_map(
                |(module_index, m)| {
                    match m {
                        ModuleLink::Ast(m) => m
                            .procedures()
                            .enumerate()
                            .filter_map(move |(i, export)| {
                                if matches!(export, Export::Alias(_)) {
                                    None
                                } else {
                                    let gid = GlobalProcedureIndex {
                                        module: ModuleIndex::new(module_index),
                                        index: ProcedureIndex::new(i),
                                    };
                                    let out_edges = self.0.callgraph.out_edges(gid);
                                    Some(DisplayModuleGraphNodeWithEdges { gid, out_edges })
                                }
                            })
                            .collect::<Vec<_>>(),
                        ModuleLink::Info(m) => m
                            .procedures()
                            .map(|(proc_index, _proc)| {
                                let gid = GlobalProcedureIndex {
                                    module: ModuleIndex::new(module_index),
                                    index: proc_index,
                                };

                                let out_edges = self.0.callgraph.out_edges(gid);
                                DisplayModuleGraphNodeWithEdges { gid, out_edges }
                            })
                            .collect::<Vec<_>>(),
                    }
                },
            ))
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraphNodes<'a>(&'a Vec<Option<ModuleLink>>);

impl fmt::Debug for DisplayModuleGraphNodes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().filter_map(|m| m.as_ref()).enumerate().flat_map(
                |(module_index, m)| {
                    let module_index = ModuleIndex::new(module_index);

                    match m {
                        ModuleLink::Ast(m) => m
                            .procedures()
                            .enumerate()
                            .filter_map(move |(proc_index, export)| {
                                if matches!(export, Export::Alias(_)) {
                                    None
                                } else {
                                    Some(DisplayModuleGraphNode {
                                        module: module_index,
                                        index: ProcedureIndex::new(proc_index),
                                        path: m.path(),
                                        proc_name: export.name(),
                                        ty: GraphNodeType::Ast,
                                    })
                                }
                            })
                            .collect::<Vec<_>>(),
                        ModuleLink::Info(m) => m
                            .procedures()
                            .map(|(proc_index, proc)| DisplayModuleGraphNode {
                                module: module_index,
                                index: proc_index,
                                path: m.path(),
                                proc_name: &proc.name,
                                ty: GraphNodeType::Compiled,
                            })
                            .collect::<Vec<_>>(),
                    }
                },
            ))
            .finish()
    }
}

#[derive(Debug)]
enum GraphNodeType {
    Ast,
    Compiled,
}

#[doc(hidden)]
struct DisplayModuleGraphNode<'a> {
    module: ModuleIndex,
    index: ProcedureIndex,
    path: &'a LibraryPath,
    proc_name: &'a ProcedureName,
    ty: GraphNodeType,
}

impl fmt::Debug for DisplayModuleGraphNode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &format_args!("{}:{}", &self.module.as_usize(), &self.index.as_usize()))
            .field("module", &self.path)
            .field("name", &self.proc_name)
            .field("type", &self.ty)
            .finish()
    }
}

#[doc(hidden)]
struct DisplayModuleGraphNodeWithEdges<'a> {
    gid: GlobalProcedureIndex,
    out_edges: &'a [GlobalProcedureIndex],
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
