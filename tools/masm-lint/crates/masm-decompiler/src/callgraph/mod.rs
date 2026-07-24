use std::collections::{HashMap, HashSet};

use miden_assembly_syntax::ast::{Invoke, path::PathBuf as MasmPathBuf};

use crate::{
    frontend::Workspace,
    symbol::{
        path::SymbolPath,
        resolution::{SymbolResolver, create_resolver},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallTarget {
    Direct(SymbolPath),
    Opaque,
}

#[derive(Debug, Clone)]
pub struct ProcNode {
    name: SymbolPath,
    module_path: SymbolPath,
    edges: Vec<CallTarget>,
}

impl ProcNode {
    pub fn name(&self) -> &SymbolPath {
        &self.name
    }

    pub(crate) fn module_path(&self) -> &SymbolPath {
        &self.module_path
    }
}

#[derive(Debug, Default)]
pub struct CallGraph {
    nodes: Vec<ProcNode>,
    name_to_id: HashMap<SymbolPath, usize>,
}

impl From<&Workspace> for CallGraph {
    fn from(ws: &Workspace) -> Self {
        let mut graph = CallGraph::default();

        for prog in ws.modules() {
            let module_path = prog.module_path().clone();
            let module_path_str = <MasmPathBuf as AsRef<str>>::as_ref(&module_path);
            let resolver = create_resolver(prog.module(), ws.source_manager());
            for proc in prog.procedures() {
                let name =
                    SymbolPath::from_module_path_and_name(module_path_str, proc.name().as_str());
                let idx = graph.nodes.len();
                graph.name_to_id.insert(name.clone(), idx);
                let edges =
                    proc.invoked().map(|invoke| edge_from_invoke(invoke, &resolver)).collect();
                graph.nodes.push(ProcNode {
                    name,
                    module_path: SymbolPath::new(module_path_str),
                    edges,
                });
            }
        }
        graph
    }
}

impl CallGraph {
    /// Returns an iterator that yields nodes in bottom-up order (leaves first,
    /// then nodes whose callees have all been processed, and so on).
    pub fn iter(&self) -> impl Iterator<Item = &ProcNode> + '_ {
        self.sorted_node_ids().into_iter().map(|idx| &self.nodes[idx])
    }

    fn sorted_node_ids(&self) -> Vec<usize> {
        // For each node, compute the set of callees
        let mut callees: HashMap<usize, HashSet<usize>> = HashMap::new();

        for idx in 0..self.nodes.len() {
            let node = &self.nodes[idx];
            let node_callees: HashSet<usize> = node
                .edges
                .iter()
                .filter_map(|target| {
                    let CallTarget::Direct(target) = target else {
                        return None;
                    };
                    self.name_to_id.get(target).copied()
                })
                .collect();
            callees.insert(idx, node_callees);
        }

        // Process nodes level by level, starting with leaves
        let mut processed_nodes: HashSet<usize> = HashSet::new();
        let mut sorted_nodes = Vec::new();

        loop {
            // Find all nodes where all callees are already processed
            let mut new_nodes: Vec<usize> = Vec::new();
            for (&node_index, node_callees) in &callees {
                if processed_nodes.contains(&node_index) {
                    continue;
                }
                if node_callees.iter().all(|c| processed_nodes.contains(c)) {
                    new_nodes.push(node_index);
                }
            }

            if new_nodes.is_empty() {
                break;
            }

            // Sort for deterministic order within each level
            new_nodes.sort();

            for node_index in new_nodes {
                sorted_nodes.push(node_index);
                processed_nodes.insert(node_index);
            }
        }

        // Append any remaining nodes (cycles) at the end
        let mut remaining_nodes: Vec<usize> =
            (0..self.nodes.len()).filter(|idx| !processed_nodes.contains(idx)).collect();
        remaining_nodes.sort();
        sorted_nodes.extend(remaining_nodes);
        sorted_nodes
    }
}

fn edge_from_invoke(invoke: &Invoke, resolver: &SymbolResolver<'_>) -> CallTarget {
    resolver
        .resolve_target(&invoke.target)
        .ok()
        .flatten()
        .map(CallTarget::Direct)
        .unwrap_or(CallTarget::Opaque)
}
