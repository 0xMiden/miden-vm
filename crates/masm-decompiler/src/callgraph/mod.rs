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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallEdge {
    target: CallTarget,
}

#[derive(Debug, Clone)]
pub struct ProcNode {
    name: SymbolPath,
    module_path: SymbolPath,
    edges: Vec<CallEdge>,
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
        CallGraphIterator::new(self)
    }
}

fn edge_from_invoke(invoke: &Invoke, resolver: &SymbolResolver<'_>) -> CallEdge {
    CallEdge {
        target: resolver
            .resolve_target(&invoke.target)
            .ok()
            .flatten()
            .map(CallTarget::Direct)
            .unwrap_or(CallTarget::Opaque),
    }
}

/// Iterator that yields nodes in bottom-up order (leaves first, then nodes
/// whose callees have all been processed, and so on). Non-SCC nodes are
/// guaranteed to come before SCC nodes.
struct CallGraphIterator<'a> {
    graph: &'a CallGraph,
    /// Collected nodes in bottom-up order
    sorted_nodes: Vec<usize>,
    /// Current index into `sorted_nodes` for iteration
    current_index: usize,
    /// Whether we've completed the initialization
    initialized: bool,
}

impl<'a> CallGraphIterator<'a> {
    fn new(graph: &'a CallGraph) -> Self {
        CallGraphIterator {
            graph,
            sorted_nodes: Vec::new(),
            current_index: 0,
            initialized: false,
        }
    }

    fn initialize(&mut self) {
        // For each node, compute the set of callees
        let mut callees: HashMap<usize, HashSet<usize>> = HashMap::new();

        for idx in 0..self.graph.nodes.len() {
            let node = &self.graph.nodes[idx];
            let node_callees: HashSet<usize> = node
                .edges
                .iter()
                .filter_map(|e| {
                    if let CallTarget::Direct(target) = &e.target {
                        self.graph.name_to_id.get(target).copied()
                    } else {
                        None
                    }
                })
                .collect();
            callees.insert(idx, node_callees);
        }

        // Process nodes level by level, starting with leaves
        let mut processed_nodes: HashSet<usize> = HashSet::new();

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
                self.sorted_nodes.push(node_index);
                processed_nodes.insert(node_index);
            }
        }

        // Append any remaining nodes (cycles) at the end
        let mut remaining_nodes: Vec<usize> = (0..self.graph.nodes.len())
            .filter(|idx| !processed_nodes.contains(idx))
            .collect();
        remaining_nodes.sort();
        self.sorted_nodes.extend(remaining_nodes);

        self.initialized = true;
    }
}

impl<'a> Iterator for CallGraphIterator<'a> {
    type Item = &'a ProcNode;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized {
            self.initialize();
        }

        if self.current_index < self.sorted_nodes.len() {
            let node_index = self.sorted_nodes[self.current_index];
            self.current_index += 1;
            Some(&self.graph.nodes[node_index])
        } else {
            None
        }
    }
}
