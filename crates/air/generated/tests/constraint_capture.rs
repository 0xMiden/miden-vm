//! Whole-AIR invariant tests over the real Miden AIRs.
//!
//! Capture uses ordinary `miden_air_source::vm::Air` values. The generated relation remains an
//! independent type and is consulted only by the shared-schema/fixed-data delegation check.

use miden_air_source::{BaseAir, Felt, vm::AIRS};
use miden_stark::capture::ir::{Class, Graph, Leaf, Node, capture, capture_into, op_counts};

#[test]
fn source_and_production_share_fixed_layout() {
    for (source, production) in AIRS.into_iter().zip(miden_air::vm::AIRS) {
        assert_eq!(source, production.source());
        assert_eq!(BaseAir::<Felt>::width(&source), BaseAir::<Felt>::width(&production));
        assert_eq!(
            BaseAir::<Felt>::preprocessed_width(&source),
            BaseAir::<Felt>::preprocessed_width(&production)
        );
        assert_eq!(
            BaseAir::<Felt>::preprocessed_trace(&source),
            BaseAir::<Felt>::preprocessed_trace(&production)
        );
        assert_eq!(
            BaseAir::<Felt>::periodic_columns(&source),
            BaseAir::<Felt>::periodic_columns(&production)
        );
    }
}

#[test]
fn capture_is_deterministic_and_well_formed() {
    for air in AIRS {
        let (g, c) = capture(&air);
        let (g2, c2) = capture(&air);
        assert_eq!(g, g2);
        assert_eq!(c.base_roots, c2.base_roots);
        assert_eq!(c.ext_roots, c2.ext_roots);
        assert_eq!(c.base_global_indices, c2.base_global_indices);
        assert_eq!(c.ext_global_indices, c2.ext_global_indices);

        // Children precede parents in dense node order.
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

        // Class soundness: base ops stay in the base world; ext ops consume ext values or
        // explicit `ExtBase` lifts; every `ExtBase` wraps a pure base subtree.
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

        // Roots and global indices stay parallel and nonempty.
        assert_eq!(c.base_roots.len(), c.base_global_indices.len());
        assert_eq!(c.ext_roots.len(), c.ext_global_indices.len());
        assert!(!c.base_roots.is_empty() || !c.ext_roots.is_empty());
        assert!(!c.ext_roots.is_empty());

        // CSE can only remove work: unique ops never exceed as-written ops, and on the
        // real AIRs must remove some.
        let (cse_base, cse_ext) = op_counts(&g);
        assert!(cse_base.total() <= c.naive_base.total());
        assert!(cse_ext.total() <= c.naive_ext.total());
        let naive = c.naive_base.total() + c.naive_ext.total();
        let cse = cse_base.total() + cse_ext.total();
        assert!(cse > 0);
        assert!(cse < naive, "expected real sharing: naive={naive} cse={cse}");
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
