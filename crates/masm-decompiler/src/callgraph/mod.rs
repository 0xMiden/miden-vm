use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use miden_assembly_syntax::{
    ast::{Invoke, InvokeKind, path::PathBuf as MasmPathBuf},
    debuginfo::DefaultSourceManager,
};

use crate::{
    frontend::{Program, Workspace},
    symbol::{
        path::SymbolPath,
        resolution::{SymbolResolver, create_resolver},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    Direct(SymbolPath),
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub kind: InvokeKind,
    pub target: CallTarget,
}

#[derive(Debug, Clone)]
pub struct ProcNode {
    pub name: SymbolPath,
    pub module_path: SymbolPath,
    pub edges: Vec<CallEdge>,
}

#[derive(Debug, Default)]
pub struct CallGraph {
    pub nodes: Vec<ProcNode>,
    pub name_to_id: HashMap<SymbolPath, usize>,
}

impl From<&Program> for CallGraph {
    fn from(program: &Program) -> Self {
        let mut graph = CallGraph::default();

        let resolver = create_resolver(program.module(), Arc::new(DefaultSourceManager::default()));
        for (idx, proc) in program.procedures().enumerate() {
            let module_path = program.module_path().clone();
            let module_path_str = <MasmPathBuf as AsRef<str>>::as_ref(&module_path);
            let name = SymbolPath::from_module_path_and_name(module_path_str, proc.name().as_str());
            let edges = proc.invoked().map(|invoke| edge_from_invoke(invoke, &resolver)).collect();
            graph.name_to_id.insert(name.clone(), idx);
            graph.nodes.push(ProcNode {
                name,
                module_path: SymbolPath::new(module_path_str),
                edges,
            });
        }
        graph
    }
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
    pub fn iter(&self) -> CallGraphIterator<'_> {
        CallGraphIterator::new(self)
    }
}

fn edge_from_invoke(invoke: &Invoke, resolver: &SymbolResolver<'_>) -> CallEdge {
    CallEdge {
        kind: invoke.kind,
        target: resolver
            .resolve_target(&invoke.target)
            .ok()
            .flatten()
            .map(CallTarget::Direct)
            .unwrap_or(CallTarget::Opaque),
    }
}

pub trait EdgeTargetString {
    fn target_string(&self) -> String;
}

impl EdgeTargetString for CallEdge {
    fn target_string(&self) -> String {
        match &self.target {
            CallTarget::Direct(s) => s.to_string(),
            CallTarget::Opaque => "unknown".to_string(),
        }
    }
}

/// Iterator that yields nodes in bottom-up order (leaves first, then nodes
/// whose callees have all been processed, and so on). Non-SCC nodes are
/// guaranteed to come before SCC nodes.
pub struct CallGraphIterator<'a> {
    graph: &'a CallGraph,
    /// Collected nodes in bottom-up order
    sorted_nodes: Vec<usize>,
    /// Current index into `sorted_nodes` for iteration
    current_index: usize,
    /// Whether we've completed the initialization
    initialized: bool,
}

impl<'a> CallGraphIterator<'a> {
    pub fn new(graph: &'a CallGraph) -> Self {
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
