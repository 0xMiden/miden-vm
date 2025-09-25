use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use crate::GlobalProcedureIndex;

/// Represents the inability to construct a topological ordering of the nodes in a [CallGraph]
/// due to a cycle in the graph, which can happen due to recursion.
#[derive(Debug)]
pub struct CycleError(BTreeSet<GlobalProcedureIndex>);

impl CycleError {
    pub fn into_node_ids(self) -> impl ExactSizeIterator<Item = GlobalProcedureIndex> {
        self.0.into_iter()
    }
}

// CALL GRAPH
// ================================================================================================

/// A [CallGraph] is a directed, acyclic graph which represents all of the edges between procedures
/// formed by a caller/callee relationship.
///
/// More precisely, this graph can be used to perform the following analyses:
///
/// - What is the maximum call stack depth for a program?
/// - Are there any recursive procedure calls?
/// - Are there procedures which are unreachable from the program entrypoint?, i.e. dead code
/// - What is the set of procedures which are reachable from a given procedure, and which of those
///   are (un)conditionally called?
///
/// A [CallGraph] is the actual graph underpinning the conceptual "module graph" of the linker, and
/// the two are intrinsically linked to one another (i.e. a [CallGraph] is meaningless without
/// the corresponding [super::Linker] state).
#[derive(Default, Clone)]
pub struct CallGraph {
    /// The adjacency matrix for procedures in the call graph
    nodes: BTreeMap<GlobalProcedureIndex, Vec<GlobalProcedureIndex>>,
}

impl CallGraph {
    /// Gets the set of edges from the given caller to its callees in the graph.
    pub fn out_edges(&self, gid: GlobalProcedureIndex) -> &[GlobalProcedureIndex] {
        self.nodes.get(&gid).map(|out_edges| out_edges.as_slice()).unwrap_or(&[])
    }

    /// Inserts a node in the graph for `id`, if not already present.
    ///
    /// Returns the set of [GlobalProcedureIndex] which are the outbound neighbors of `id` in the
    /// graph, i.e. the callees of a call-like instruction.
    pub fn get_or_insert_node(
        &mut self,
        id: GlobalProcedureIndex,
    ) -> &mut Vec<GlobalProcedureIndex> {
        self.nodes.entry(id).or_default()
    }

    /// Add an edge in the call graph from `caller` to `callee`.
    ///
    /// This operation is unchecked, i.e. it is possible to introduce cycles in the graph using it.
    /// As a result, it is essential that the caller either know that adding the edge does _not_
    /// introduce a cycle, or that [Self::toposort] is run once the graph is built, in order to
    /// verify that the graph is valid and has no cycles.
    ///
    /// NOTE: This function will panic if you attempt to add an edge from a function to itself,
    /// which trivially introduces a cycle. All other cycle-inducing edges must be caught by a
    /// call to [Self::toposort].
    pub fn add_edge(&mut self, caller: GlobalProcedureIndex, callee: GlobalProcedureIndex) {
        assert_ne!(caller, callee, "a procedure cannot call itself");

        // Make sure the callee is in the graph
        self.get_or_insert_node(callee);
        // Make sure the caller is in the graph
        let callees = self.get_or_insert_node(caller);
        // If the caller already references the callee, we're done
        if callees.contains(&callee) {
            return;
        }

        callees.push(callee);
    }

    /// Removes the edge between `caller` and `callee` from the graph
    pub fn remove_edge(&mut self, caller: GlobalProcedureIndex, callee: GlobalProcedureIndex) {
        if let Some(out_edges) = self.nodes.get_mut(&caller) {
            out_edges.retain(|n| *n != callee);
        }
    }

    /// Returns the number of predecessors of `id` in the graph, i.e.
    /// the number of procedures which call `id`.
    pub fn num_predecessors(&self, id: GlobalProcedureIndex) -> usize {
        self.nodes.iter().filter(|(_, out_edges)| out_edges.contains(&id)).count()
    }

    /// Construct the topological ordering of all nodes in the call graph.
    ///
    /// Returns `Err` if a cycle is detected in the graph
    pub fn toposort(&self) -> Result<Vec<GlobalProcedureIndex>, CycleError> {
        if self.nodes.is_empty() {
            return Ok(vec![]);
        }

        let mut output = Vec::with_capacity(self.nodes.len());
        let mut graph = self.clone();

        // Build the set of roots by finding all nodes
        // that have no predecessors
        let mut has_preds = BTreeSet::default();
        for (_node, out_edges) in graph.nodes.iter() {
            for succ in out_edges.iter() {
                has_preds.insert(*succ);
            }
        }
        let mut roots =
            VecDeque::from_iter(graph.nodes.keys().copied().filter(|n| !has_preds.contains(n)));

        // If all nodes have predecessors, there must be a cycle, so just pick a node and let the
        // algorithm find the cycle for that node so we have a useful error. Set a flag so that we
        // can assert that the cycle was actually found as a sanity check
        let mut expect_cycle = false;
        if roots.is_empty() {
            expect_cycle = true;
            roots.extend(graph.nodes.keys().next());
        }

        let mut successors = Vec::with_capacity(4);
        while let Some(id) = roots.pop_front() {
            output.push(id);
            successors.clear();
            successors.extend(graph.nodes[&id].iter().copied());
            for mid in successors.drain(..) {
                graph.remove_edge(id, mid);
                if graph.num_predecessors(mid) == 0 {
                    roots.push_back(mid);
                }
            }
        }

        let has_cycle = graph
            .nodes
            .iter()
            .any(|(n, out_edges)| !output.contains(n) || !out_edges.is_empty());
        if has_cycle {
            let mut in_cycle = BTreeSet::default();
            for (n, edges) in graph.nodes.iter() {
                if edges.is_empty() {
                    continue;
                }
                in_cycle.insert(*n);
                in_cycle.extend(edges.as_slice());
            }
            Err(CycleError(in_cycle))
        } else {
            assert!(!expect_cycle, "we expected a cycle to be found, but one was not identified");
            Ok(output)
        }
    }

    /// Gets a new graph which is a subgraph of `self` containing all of the nodes reachable from
    /// `root`, and nothing else.
    pub fn subgraph(&self, root: GlobalProcedureIndex) -> Self {
        let mut worklist = VecDeque::from_iter([root]);
        let mut graph = Self::default();
        let mut visited = BTreeSet::default();

        while let Some(gid) = worklist.pop_front() {
            if !visited.insert(gid) {
                continue;
            }

            let new_successors = graph.get_or_insert_node(gid);
            let prev_successors = self.out_edges(gid);
            worklist.extend(prev_successors.iter().cloned());
            new_successors.extend_from_slice(prev_successors);
        }

        graph
    }

    /// Constructs the topological ordering of nodes in the call graph, for which `caller` is an
    /// ancestor.
    ///
    /// # Errors
    /// Returns an error if a cycle is detected in the graph.
    pub fn toposort_caller(
        &self,
        caller: GlobalProcedureIndex,
    ) -> Result<Vec<GlobalProcedureIndex>, CycleError> {
        let mut output = Vec::with_capacity(self.nodes.len());

        // Build a subgraph of `self` containing only those nodes reachable from `caller`
        let mut graph = self.subgraph(caller);

        // Remove all predecessor edges to `caller`
        graph.nodes.iter_mut().for_each(|(_pred, out_edges)| {
            out_edges.retain(|n| *n != caller);
        });

        let mut roots = VecDeque::from_iter([caller]);
        let mut successors = Vec::with_capacity(4);
        while let Some(id) = roots.pop_front() {
            output.push(id);
            successors.clear();
            successors.extend(graph.nodes[&id].iter().copied());
            for mid in successors.drain(..) {
                graph.remove_edge(id, mid);
                if graph.num_predecessors(mid) == 0 {
                    roots.push_back(mid);
                }
            }
        }

        let has_cycle = graph
            .nodes
            .iter()
            .any(|(n, out_edges)| output.contains(n) && !out_edges.is_empty());
        if has_cycle {
            let mut in_cycle = BTreeSet::default();
            for (n, edges) in graph.nodes.iter() {
                if edges.is_empty() {
                    continue;
                }
                in_cycle.insert(*n);
                in_cycle.extend(edges.as_slice());
            }
            Err(CycleError(in_cycle))
        } else {
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GlobalProcedureIndex, ModuleIndex, ast::ProcedureIndex};

    const A: ModuleIndex = ModuleIndex::const_new(1);
    const B: ModuleIndex = ModuleIndex::const_new(2);
    const P1: ProcedureIndex = ProcedureIndex::const_new(1);
    const P2: ProcedureIndex = ProcedureIndex::const_new(2);
    const P3: ProcedureIndex = ProcedureIndex::const_new(3);
    const A1: GlobalProcedureIndex = GlobalProcedureIndex { module: A, index: P1 };
    const A2: GlobalProcedureIndex = GlobalProcedureIndex { module: A, index: P2 };
    const A3: GlobalProcedureIndex = GlobalProcedureIndex { module: A, index: P3 };
    const B1: GlobalProcedureIndex = GlobalProcedureIndex { module: B, index: P1 };
    const B2: GlobalProcedureIndex = GlobalProcedureIndex { module: B, index: P2 };
    const B3: GlobalProcedureIndex = GlobalProcedureIndex { module: B, index: P3 };

    #[test]
    fn callgraph_add_edge() {
        let graph = callgraph_simple();

        // Verify the graph structure
        assert_eq!(graph.num_predecessors(A1), 0);
        assert_eq!(graph.num_predecessors(B1), 0);
        assert_eq!(graph.num_predecessors(A2), 1);
        assert_eq!(graph.num_predecessors(B2), 2);
        assert_eq!(graph.num_predecessors(B3), 1);
        assert_eq!(graph.num_predecessors(A3), 2);

        assert_eq!(graph.out_edges(A1), &[A2]);
        assert_eq!(graph.out_edges(B1), &[B2]);
        assert_eq!(graph.out_edges(A2), &[B2, A3]);
        assert_eq!(graph.out_edges(B2), &[B3]);
        assert_eq!(graph.out_edges(A3), &[]);
        assert_eq!(graph.out_edges(B3), &[A3]);
    }

    #[test]
    fn callgraph_add_edge_with_cycle() {
        let graph = callgraph_cycle();

        // Verify the graph structure
        assert_eq!(graph.num_predecessors(A1), 0);
        assert_eq!(graph.num_predecessors(B1), 0);
        assert_eq!(graph.num_predecessors(A2), 2);
        assert_eq!(graph.num_predecessors(B2), 2);
        assert_eq!(graph.num_predecessors(B3), 1);
        assert_eq!(graph.num_predecessors(A3), 1);

        assert_eq!(graph.out_edges(A1), &[A2]);
        assert_eq!(graph.out_edges(B1), &[B2]);
        assert_eq!(graph.out_edges(A2), &[B2]);
        assert_eq!(graph.out_edges(B2), &[B3]);
        assert_eq!(graph.out_edges(A3), &[A2]);
        assert_eq!(graph.out_edges(B3), &[A3]);
    }

    #[test]
    fn callgraph_subgraph() {
        let graph = callgraph_simple();
        let subgraph = graph.subgraph(A2);

        assert_eq!(subgraph.nodes.keys().copied().collect::<Vec<_>>(), vec![A2, A3, B2, B3]);
    }

    #[test]
    fn callgraph_with_cycle_subgraph() {
        let graph = callgraph_cycle();
        let subgraph = graph.subgraph(A2);

        assert_eq!(subgraph.nodes.keys().copied().collect::<Vec<_>>(), vec![A2, A3, B2, B3]);
    }

    #[test]
    fn callgraph_toposort() {
        let graph = callgraph_simple();

        let sorted = graph.toposort().expect("expected valid topological ordering");
        assert_eq!(sorted.as_slice(), &[A1, B1, A2, B2, B3, A3]);
    }

    #[test]
    fn callgraph_toposort_caller() {
        let graph = callgraph_simple();

        let sorted = graph.toposort_caller(A2).expect("expected valid topological ordering");
        assert_eq!(sorted.as_slice(), &[A2, B2, B3, A3]);
    }

    #[test]
    fn callgraph_with_cycle_toposort() {
        let graph = callgraph_cycle();

        let err = graph.toposort().expect_err("expected topological sort to fail with cycle");
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A2, A3, B2, B3]);
    }

    /// a::a1 -> a::a2 -> a::a3
    ///            |        ^
    ///            v        |
    /// b::b1 -> b::b2 -> b::b3
    fn callgraph_simple() -> CallGraph {
        // Construct the graph
        let mut graph = CallGraph::default();
        graph.add_edge(A1, A2);
        graph.add_edge(B1, B2);
        graph.add_edge(A2, B2);
        graph.add_edge(A2, A3);
        graph.add_edge(B2, B3);
        graph.add_edge(B3, A3);

        graph
    }

    /// a::a1 -> a::a2 <- a::a3
    ///            |        ^
    ///            v        |
    /// b::b1 -> b::b2 -> b::b3
    fn callgraph_cycle() -> CallGraph {
        // Construct the graph
        let mut graph = CallGraph::default();
        graph.add_edge(A1, A2);
        graph.add_edge(B1, B2);
        graph.add_edge(A2, B2);
        graph.add_edge(B2, B3);
        graph.add_edge(B3, A3);
        graph.add_edge(A3, A2);

        graph
    }
}
