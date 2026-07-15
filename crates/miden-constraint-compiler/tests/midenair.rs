//! Whole-AIR invariant tests over the real Miden AIRs.
//!
//! Capture goes through [`HandwrittenMidenAir`]: `MidenAir::eval` routes to the
//! generated evaluators, and these tests exercise the capture frontend on the
//! hand-written definitions (crate invariant 1).

use miden_air::{HandwrittenMidenAir, MIDEN_AIR_COUNT, MidenAir};
use miden_constraint_compiler::ir::{Class, Graph, Leaf, Node, capture, capture_into, op_counts};

const AIRS: [HandwrittenMidenAir; MIDEN_AIR_COUNT] = [
    HandwrittenMidenAir(MidenAir::Core),
    HandwrittenMidenAir(MidenAir::Chiplets),
    HandwrittenMidenAir(MidenAir::Poseidon2Permutation),
];

#[test]
fn capture_is_deterministic() {
    for air in AIRS {
        let (g1, c1) = capture(&air);
        let (g2, c2) = capture(&air);
        assert_eq!(g1, g2);
        assert_eq!(c1.base_roots, c2.base_roots);
        assert_eq!(c1.ext_roots, c2.ext_roots);
        assert_eq!(c1.base_global_indices, c2.base_global_indices);
        assert_eq!(c1.ext_global_indices, c2.ext_global_indices);
    }
}

#[test]
fn ids_are_dense_and_topological() {
    for air in AIRS {
        let (g, _) = capture(&air);
        for (id, node) in g.iter() {
            match node {
                Node::Op { x, y, .. } => {
                    assert!(x < id);
                    if let Some(y) = y {
                        assert!(y < id);
                    }
                },
                Node::Leaf(Leaf::ExtBase(inner)) => assert!(inner < id),
                Node::Leaf(_) => {},
            }
        }
    }
}

/// The structural-equality primitive drift tests build on: capturing the same
/// constraints twice into one shared builder yields identical per-constraint root
/// ids (hash-consing canonicalizes both captures onto the same nodes).
#[test]
fn shared_builder_capture_gives_equal_roots() {
    for air in AIRS {
        let mut b = Graph::builder();
        let c1 = capture_into(&air, &mut b);
        let len_after_first = b.len();
        let c2 = capture_into(&air, &mut b);
        assert_eq!(c1.base_roots, c2.base_roots);
        assert_eq!(c1.ext_roots, c2.ext_roots);
        // The second capture must not create a single new node.
        assert_eq!(b.len(), len_after_first);
    }
}

/// Class soundness: base ops stay in the base world; ext ops consume ext values or
/// explicit `ExtBase` lifts; every `ExtBase` wraps a pure base subtree.
#[test]
fn classes_are_sound() {
    for air in AIRS {
        let (g, _) = capture(&air);
        for (_, node) in g.iter() {
            match node {
                Node::Op { class: Class::Base, x, y, .. } => {
                    for c in [Some(x), y].into_iter().flatten() {
                        assert_eq!(g.class(c), Class::Base);
                        assert!(
                            !matches!(g.node(c), Node::Leaf(Leaf::ExtBase(_))),
                            "base op consumes an ExtBase lift"
                        );
                    }
                },
                Node::Op { class: Class::Ext, x, y, .. } => {
                    for c in [Some(x), y].into_iter().flatten() {
                        let is_lift = matches!(g.node(c), Node::Leaf(Leaf::ExtBase(_)));
                        assert!(
                            g.class(c) == Class::Ext || is_lift,
                            "ext op consumes an unlifted base value"
                        );
                    }
                },
                Node::Leaf(Leaf::ExtBase(inner)) => {
                    assert_eq!(g.class(inner), Class::Base);
                    assert!(
                        !matches!(g.node(inner), Node::Leaf(Leaf::ExtBase(_))),
                        "nested ExtBase lift"
                    );
                },
                Node::Leaf(_) => {},
            }
        }
    }
}

#[test]
fn roots_and_indices_are_parallel_and_nonempty() {
    for air in AIRS {
        let (_, c) = capture(&air);
        assert_eq!(c.base_roots.len(), c.base_global_indices.len());
        assert_eq!(c.ext_roots.len(), c.ext_global_indices.len());
        assert!(!c.base_roots.is_empty());
        assert!(!c.ext_roots.is_empty());
    }
}

/// CSE can only remove work: unique ops never exceed as-written ops, and on the
/// real AIRs must remove a meaningful amount.
#[test]
fn cse_only_removes_work() {
    for air in AIRS {
        let (g, c) = capture(&air);
        let (cse_base, cse_ext) = op_counts(&g);
        assert!(cse_base.total() <= c.naive_base.total());
        assert!(cse_ext.total() <= c.naive_ext.total());
        let naive = c.naive_base.total() + c.naive_ext.total();
        let cse = cse_base.total() + cse_ext.total();
        assert!(cse > 0);
        assert!(cse < naive, "expected real sharing: naive={naive} cse={cse}");
    }
}
