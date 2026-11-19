//! Whole-AIR invariant tests over the real Miden AIRs.
//!
//! Capture uses the authored [`miden_air_definitions::vm::MidenAir`] directly, exercising the
//! hand-written definitions (`miden-constraint-compiler` crate invariant 1).
//!
//! Lives here rather than in the compiler crate so `miden-constraint-compiler`
//! carries no dev-dependency on `miden-air`, keeping the release order acyclic:
//! `miden-constraint-compiler` → `miden-ace` → `miden-air`.

use miden_air_definitions::vm::AIRS;
use miden_constraint_compiler::ir::{
    Class, Graph, Leaf, Node, capture_native, capture_native_into, op_counts,
};

#[test]
fn captures_are_deterministic_and_reuse_shared_graph_nodes() {
    for air in AIRS {
        let mut builder = Graph::builder();
        let (first, _) = capture_native_into(&air, &mut builder).unwrap();
        let first_len = builder.len();
        let (shared, _) = capture_native_into(&air, &mut builder).unwrap();
        assert_eq!(builder.len(), first_len);
        assert_eq!(first.base_roots, shared.base_roots);
        assert_eq!(first.ext_roots, shared.ext_roots);

        let (graph, independent, _) = capture_native(&air).unwrap();
        assert_eq!(builder.freeze(), graph);
        assert_eq!(first.base_roots, independent.base_roots);
        assert_eq!(first.ext_roots, independent.ext_roots);
        assert_eq!(first.base_global_indices, independent.base_global_indices);
        assert_eq!(first.ext_global_indices, independent.ext_global_indices);
        assert_eq!(first.base_roots.len(), first.base_global_indices.len());
        assert_eq!(first.ext_roots.len(), first.ext_global_indices.len());
        assert!(!first.ext_roots.is_empty());

        // CSE must remove work on the real AIRs.
        let (cse_base, cse_ext) = op_counts(&graph);
        assert!(cse_base.total() <= first.naive_base.total());
        assert!(cse_ext.total() <= first.naive_ext.total());
        let naive = first.naive_base.total() + first.naive_ext.total();
        let cse = cse_base.total() + cse_ext.total();
        assert!(
            cse > 0 && cse < naive,
            "{air:?}: expected real sharing: naive={naive} cse={cse}"
        );
    }
}

#[test]
fn graph_edges_are_topological_and_preserve_expression_classes() {
    for air in AIRS {
        let (graph, ..) = capture_native(&air).unwrap();
        for (id, node) in graph.iter() {
            match node {
                Node::Op { class, x, y, .. } => {
                    for child in [Some(x), y].into_iter().flatten() {
                        assert!(child < id);
                        let is_lift = matches!(graph.node(child), Node::Leaf(Leaf::ExtBase(_)));
                        match class {
                            Class::Base => assert!(graph.class(child) == Class::Base && !is_lift),
                            Class::Ext => assert!(graph.class(child) == Class::Ext || is_lift),
                        }
                    }
                },
                Node::Leaf(Leaf::ExtBase(inner)) => {
                    assert!(inner < id);
                    assert_eq!(graph.class(inner), Class::Base);
                    assert!(!matches!(graph.node(inner), Node::Leaf(Leaf::ExtBase(_))));
                },
                Node::Leaf(_) => {},
            }
        }
    }
}
