use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use crate::GlobalItemIndex;

/// Represents the inability to construct a topological ordering of the nodes in a [CallGraph]
/// due to a cycle in the graph, which can happen due to recursion.
#[derive(Debug)]
pub struct CycleError(BTreeSet<GlobalItemIndex>);

impl CycleError {
    pub fn new(nodes: impl IntoIterator<Item = GlobalItemIndex>) -> Self {
        Self(nodes.into_iter().collect())
    }

    pub fn into_node_ids(self) -> impl ExactSizeIterator<Item = GlobalItemIndex> {
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
    nodes: BTreeMap<GlobalItemIndex, Vec<GlobalItemIndex>>,
}

impl CallGraph {
    /// Gets the set of edges from the given caller to its callees in the graph.
    pub fn out_edges(&self, gid: GlobalItemIndex) -> &[GlobalItemIndex] {
        self.nodes.get(&gid).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Inserts a node in the graph for `id`, if not already present.
    ///
    /// Returns the set of [GlobalItemIndex] which are the outbound neighbors of `id` in the
    /// graph, i.e. the callees of a call-like instruction.
    pub fn get_or_insert_node(&mut self, id: GlobalItemIndex) -> &mut Vec<GlobalItemIndex> {
        self.nodes.entry(id).or_default()
    }

    /// Add an edge in the call graph from `caller` to `callee`.
    ///
    /// This operation is unchecked, i.e. it is possible to introduce cycles in the graph using it.
    /// As a result, it is essential that the caller either know that adding the edge does _not_
    /// introduce a cycle, or that [Self::toposort] is run once the graph is built, in order to
    /// verify that the graph is valid and has no cycles.
    ///
    /// Returns an error if adding the edge would introduce a trivial self-cycle.
    pub fn add_edge(
        &mut self,
        caller: GlobalItemIndex,
        callee: GlobalItemIndex,
    ) -> Result<(), CycleError> {
        if caller == callee {
            return Err(CycleError::new([caller]));
        }

        // Make sure the callee is in the graph
        self.get_or_insert_node(callee);
        // Make sure the caller is in the graph
        let callees = self.get_or_insert_node(caller);
        // If the caller already references the callee, we're done
        if callees.contains(&callee) {
            return Ok(());
        }

        callees.push(callee);
        Ok(())
    }

    /// Removes the edge between `caller` and `callee` from the graph
    pub fn remove_edge(&mut self, caller: GlobalItemIndex, callee: GlobalItemIndex) {
        if let Some(out_edges) = self.nodes.get_mut(&caller) {
            out_edges.retain(|n| *n != callee);
        }
    }

    /// Returns the number of predecessors of `id` in the graph, i.e.
    /// the number of procedures which call `id`.
    pub fn num_predecessors(&self, id: GlobalItemIndex) -> usize {
        self.nodes.iter().filter(|(_, out_edges)| out_edges.contains(&id)).count()
    }

    /// Construct the topological ordering of all nodes in the call graph.
    ///
    /// Uses Kahn's algorithm with pre-computed in-degrees for O(V + E) complexity.
    ///
    /// Returns `Err` if a cycle is detected in the graph
    pub fn toposort(&self) -> Result<Vec<GlobalItemIndex>, CycleError> {
        if self.nodes.is_empty() {
            return Ok(vec![]);
        }

        let num_nodes = self.nodes.len();
        let mut output = Vec::with_capacity(num_nodes);

        // Compute in-degree for each node: O(V + E)
        let mut in_degree: BTreeMap<GlobalItemIndex, usize> =
            self.nodes.keys().map(|&k| (k, 0)).collect();
        for out_edges in self.nodes.values() {
            for &succ in out_edges {
                *in_degree.entry(succ).or_default() += 1;
            }
        }

        // Seed the queue with all zero-in-degree nodes: O(V)
        let mut queue: VecDeque<GlobalItemIndex> =
            in_degree.iter().filter(|&(_, &deg)| deg == 0).map(|(&n, _)| n).collect();

        // Kahn's algorithm: process each node exactly once, each edge exactly once → O(V + E)
        while let Some(id) = queue.pop_front() {
            output.push(id);
            for &mid in self.out_edges(id) {
                let deg = in_degree.get_mut(&mid).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(mid);
                }
            }
        }

        // If not all nodes were visited, the remaining nodes participate in cycles
        if output.len() != num_nodes {
            let visited: BTreeSet<GlobalItemIndex> = output.iter().copied().collect();
            let mut in_cycle = BTreeSet::default();
            for (&n, out_edges) in self.nodes.iter() {
                if visited.contains(&n) {
                    continue;
                }
                in_cycle.insert(n);
                for &succ in out_edges {
                    if !visited.contains(&succ) {
                        in_cycle.insert(succ);
                    }
                }
            }
            Err(CycleError(in_cycle))
        } else {
            Ok(output)
        }
    }

    /// Gets a new graph which is a subgraph of `self` containing all of the nodes reachable from
    /// `root`, and nothing else.
    pub fn subgraph(&self, root: GlobalItemIndex) -> Self {
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

    /// Computes the set of nodes in this graph which can reach `root`.
    fn reverse_reachable(&self, root: GlobalItemIndex) -> BTreeSet<GlobalItemIndex> {
        // Build reverse adjacency map: O(V + E)
        let mut predecessors: BTreeMap<GlobalItemIndex, Vec<GlobalItemIndex>> =
            self.nodes.keys().map(|&k| (k, Vec::new())).collect();
        for (&node, out_edges) in self.nodes.iter() {
            for &succ in out_edges {
                predecessors.entry(succ).or_default().push(node);
            }
        }

        // BFS on reverse graph: O(V + E)
        let mut worklist = VecDeque::from_iter([root]);
        let mut visited = BTreeSet::default();

        while let Some(gid) = worklist.pop_front() {
            if !visited.insert(gid) {
                continue;
            }

            if let Some(preds) = predecessors.get(&gid) {
                worklist.extend(preds.iter().copied());
            }
        }

        visited
    }

    /// Constructs the topological ordering of nodes in the call graph, for which `caller` is an
    /// ancestor.
    ///
    /// Uses Kahn's algorithm with pre-computed in-degrees for O(V + E) complexity.
    ///
    /// # Errors
    /// Returns an error if a cycle is detected in the graph.
    pub fn toposort_caller(
        &self,
        caller: GlobalItemIndex,
    ) -> Result<Vec<GlobalItemIndex>, CycleError> {
        // Build a subgraph of `self` containing only those nodes reachable from `caller`
        let subgraph = self.subgraph(caller);
        let num_nodes = subgraph.nodes.len();
        let mut output = Vec::with_capacity(num_nodes);

        // Compute in-degree for each node in the subgraph: O(V + E)
        let mut in_degree: BTreeMap<GlobalItemIndex, usize> =
            subgraph.nodes.keys().map(|&k| (k, 0)).collect();
        for out_edges in subgraph.nodes.values() {
            for &succ in out_edges {
                *in_degree.entry(succ).or_default() += 1;
            }
        }

        // Check if any cycle closes back to `caller` (i.e. caller has predecessors in its
        // own reachable subgraph)
        let caller_has_predecessors = in_degree.get(&caller).copied().unwrap_or(0) > 0;

        // Force `caller` as the root by zeroing its in-degree (equivalent to removing
        // all back-edges to `caller`)
        in_degree.insert(caller, 0);

        // Seed queue with `caller` as the sole root
        let mut queue = VecDeque::from_iter([caller]);

        // Kahn's algorithm: O(V + E)
        while let Some(id) = queue.pop_front() {
            output.push(id);
            for &mid in subgraph.out_edges(id) {
                // Skip back-edges to caller (already processed as root)
                if mid == caller {
                    continue;
                }
                let deg = in_degree.get_mut(&mid).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(mid);
                }
            }
        }

        // Detect cycles: either caller had predecessors in its subgraph (a cycle closes
        // back to it), or not all nodes were reachable (an internal cycle)
        let has_cycle = caller_has_predecessors || output.len() != num_nodes;
        if has_cycle {
            let visited: BTreeSet<GlobalItemIndex> = output.iter().copied().collect();
            let mut in_cycle = BTreeSet::default();

            // Collect nodes not processed by the sort (they're in internal cycles)
            for (&n, out_edges) in subgraph.nodes.iter() {
                if !visited.contains(&n) {
                    in_cycle.insert(n);
                    for &succ in out_edges {
                        if !visited.contains(&succ) {
                            in_cycle.insert(succ);
                        }
                    }
                }
            }

            // If caller has back-edges, include all nodes participating in the cycle
            // through caller
            if caller_has_predecessors {
                in_cycle.extend(subgraph.reverse_reachable(caller));
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
    use crate::{GlobalItemIndex, ModuleIndex, ast::ItemIndex};

    const A: ModuleIndex = ModuleIndex::const_new(1);
    const B: ModuleIndex = ModuleIndex::const_new(2);
    const P1: ItemIndex = ItemIndex::const_new(1);
    const P2: ItemIndex = ItemIndex::const_new(2);
    const P3: ItemIndex = ItemIndex::const_new(3);
    const A1: GlobalItemIndex = GlobalItemIndex { module: A, index: P1 };
    const A2: GlobalItemIndex = GlobalItemIndex { module: A, index: P2 };
    const A3: GlobalItemIndex = GlobalItemIndex { module: A, index: P3 };
    const B1: GlobalItemIndex = GlobalItemIndex { module: B, index: P1 };
    const B2: GlobalItemIndex = GlobalItemIndex { module: B, index: P2 };
    const B3: GlobalItemIndex = GlobalItemIndex { module: B, index: P3 };

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

    #[test]
    fn callgraph_toposort_caller_with_reachable_cycle() {
        let graph = callgraph_cycle();

        let err = graph
            .toposort_caller(A1)
            .expect_err("expected toposort_caller to fail when a reachable cycle exists");
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A2, A3, B2, B3]);
    }

    #[test]
    fn callgraph_toposort_caller_root_closing_cycle() {
        let graph = callgraph_cycle();

        let err = graph
            .toposort_caller(A2)
            .expect_err("expected toposort_caller to detect cycle closing back into root");
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A2, A3, B2, B3]);
    }

    #[test]
    fn callgraph_add_edge_with_self_cycle_is_error() {
        let mut graph = CallGraph::default();

        let err = graph.add_edge(A1, A1).expect_err("expected self-edge to be rejected");
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A1]);
    }

    #[test]
    fn callgraph_rootless_cycle_toposort_is_error() {
        let mut graph = CallGraph::default();
        graph.add_edge(A1, B1).expect("A1 -> B1 must be accepted");
        graph.add_edge(B1, A1).expect("B1 -> A1 must be accepted");

        let err = graph.toposort().expect_err("expected topological sort to fail with cycle");
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A1, B1]);
    }

    #[test]
    fn callgraph_toposort_whole_graph_cycle_without_roots() {
        let graph = callgraph_cycle_without_roots();
        let err = graph.toposort().expect_err(
            "expected topological sort to fail when every node is blocked behind a cycle",
        );
        assert_eq!(err.0.into_iter().collect::<Vec<_>>(), &[A1, A2, A3]);
    }

    /// a::a1 -> a::a2 -> a::a3
    ///            |        ^
    ///            v        |
    /// b::b1 -> b::b2 -> b::b3
    fn callgraph_simple() -> CallGraph {
        // Construct the graph
        let mut graph = CallGraph::default();
        graph.add_edge(A1, A2).expect("A1 -> A2 must be accepted");
        graph.add_edge(B1, B2).expect("B1 -> B2 must be accepted");
        graph.add_edge(A2, B2).expect("A2 -> B2 must be accepted");
        graph.add_edge(A2, A3).expect("A2 -> A3 must be accepted");
        graph.add_edge(B2, B3).expect("B2 -> B3 must be accepted");
        graph.add_edge(B3, A3).expect("B3 -> A3 must be accepted");

        graph
    }

    /// a::a1 -> a::a2 <- a::a3
    ///            |        ^
    ///            v        |
    /// b::b1 -> b::b2 -> b::b3
    fn callgraph_cycle() -> CallGraph {
        // Construct the graph
        let mut graph = CallGraph::default();
        graph.add_edge(A1, A2).expect("A1 -> A2 must be accepted");
        graph.add_edge(B1, B2).expect("B1 -> B2 must be accepted");
        graph.add_edge(A2, B2).expect("A2 -> B2 must be accepted");
        graph.add_edge(B2, B3).expect("B2 -> B3 must be accepted");
        graph.add_edge(B3, A3).expect("B3 -> A3 must be accepted");
        graph.add_edge(A3, A2).expect("A3 -> A2 must be accepted");

        graph
    }

    /// a::a1 -> a::a2 -> a::a3
    ///   ^                 |
    ///   +-----------------+
    ///
    /// Every node has in-degree 1, so Kahn's algorithm starts with an empty queue.
    fn callgraph_cycle_without_roots() -> CallGraph {
        let mut graph = CallGraph::default();
        graph.add_edge(A1, A2).expect("A1 -> A2 must be accepted");
        graph.add_edge(A2, A3).expect("A2 -> A3 must be accepted");
        graph.add_edge(A3, A1).expect("A3 -> A1 must be accepted");

        graph
    }
}
