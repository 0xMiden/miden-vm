//! Lowering from the captured constraint IR to the verifier DAG.
//!
//! IR-driven counterpart of [`super::lower`]: the verifier expression is
//! documented there and built identically here; only the per-constraint input
//! representation differs (a hash-consed [`Graph`] instead of symbolic
//! expression trees).
//!
//! # Digest-critical invariant
//!
//! `DagBuilder` interning order is digest-visible. Nodes are therefore
//! materialized by demand-driven, per-constraint recursive DFS from each
//! constraint root in global layout order — never by IR node-id order — so the
//! builder-call sequence replicates the symbolic-tree lowering exactly. The
//! node-for-node differential tests in `miden-air` (`tests/ace_codegen.rs`)
//! enforce this over all supported Miden AIRs.
//!
//! The IR's base/ext class split is erased here: every DAG value is an
//! extension-field element, and [`Leaf::ExtBase`] lowers transparently to its
//! wrapped subtree (mirroring the tree lowering's `ExtLeaf::Base` case). Fields
//! are concrete (`Felt`/`QuadFelt`), matching the capture frontend.

use miden_constraint_compiler::ir::{
    CapturedConstraints, Graph, Leaf, Node, NodeId as IrNodeId, OpKind,
};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{BasedVectorSpace, PrimeCharacteristicRing};

use super::{
    builder::DagBuilder,
    ir::{AceDag, NodeId, PeriodicColumnData},
    lower::build_periodic_nodes,
};
use crate::{
    layout::{InputKey, InputLayout},
    quotient::build_quotient_recomposition_dag,
    randomness,
};

/// Build the verifier-equivalent root expression DAG from a captured
/// constraint graph.
///
/// Equivalent to [`super::lower::build_verifier_dag`] with the per-constraint
/// lowering driven by the IR; see the module docs there for the expression
/// being built.
pub fn build_verifier_dag_from_ir(
    graph: &Graph,
    constraints: &CapturedConstraints,
    layout: &InputLayout,
    periodic: Option<&PeriodicColumnData<QuadFelt>>,
) -> AceDag<QuadFelt> {
    let mut builder = DagBuilder::<QuadFelt>::new();
    let periodic_nodes = match periodic {
        Some(data) => build_periodic_nodes(&mut builder, layout, data),
        None => Vec::new(),
    };
    let alpha = builder.input(InputKey::Alpha);

    // Merge base and extension constraints in evaluation order using the
    // captured global indices.
    let total = constraints.base_global_indices.len() + constraints.ext_global_indices.len();
    let mut ordered: Vec<(usize, bool, usize)> = Vec::with_capacity(total);
    for (i, &pos) in constraints.base_global_indices.iter().enumerate() {
        ordered.push((pos, false, i));
    }
    for (i, &pos) in constraints.ext_global_indices.iter().enumerate() {
        ordered.push((pos, true, i));
    }
    ordered.sort_by_key(|(pos, ..)| *pos);

    let mut acc = builder.constant(QuadFelt::ZERO);
    for &(_, is_ext, idx) in &ordered {
        let root = if is_ext {
            constraints.ext_roots[idx]
        } else {
            constraints.base_roots[idx]
        };
        let node = lower_ir_expr(graph, root, &mut builder, layout, &periodic_nodes);
        let acc_mul = builder.mul(acc, alpha);
        acc = builder.add(acc_mul, node);
    }

    let quotient = build_quotient_recomposition_dag::<Felt, QuadFelt>(&mut builder, layout);
    let z_pow_n = builder.input(InputKey::ZPowN);
    let one = builder.constant(QuadFelt::ONE);
    let vanishing = builder.sub(z_pow_n, one);
    let q_times_v = builder.mul(quotient, vanishing);
    let root = builder.sub(acc, q_times_v);

    builder.build(root)
}

/// Lower one constraint expression by recursive DFS from `id`, left child
/// before right, mirroring the symbolic-tree lowering's builder-call order.
fn lower_ir_expr(
    graph: &Graph,
    id: IrNodeId,
    builder: &mut DagBuilder<QuadFelt>,
    layout: &InputLayout,
    periodic_nodes: &[NodeId],
) -> NodeId {
    match graph.node(id) {
        Node::Leaf(leaf) => match leaf {
            Leaf::Main { offset, index } => builder.input(InputKey::Main { offset, index }),
            Leaf::Public(index) => builder.input(InputKey::Public(index)),
            Leaf::Periodic(index) => periodic_nodes[index],
            Leaf::IsFirst => builder.input(InputKey::IsFirst),
            Leaf::IsLast => builder.input(InputKey::IsLast),
            Leaf::IsTransition => builder.input(InputKey::IsTransition),
            Leaf::BaseConst(raw) => builder.constant(QuadFelt::from(Felt::from_u64(raw))),
            Leaf::Aux { offset, index } => {
                // Reconstruct the extension element from its base coordinates,
                // in the exact node order of the tree lowering.
                let mut acc = builder.constant(QuadFelt::ZERO);
                for coord in 0..<QuadFelt as BasedVectorSpace<Felt>>::DIMENSION {
                    let basis = <QuadFelt as BasedVectorSpace<Felt>>::ith_basis_element(coord)
                        .expect("basis index within extension degree");
                    let coord_node = builder.input(InputKey::AuxCoord { offset, index, coord });
                    let basis_node = builder.constant(basis);
                    let term = builder.mul(basis_node, coord_node);
                    acc = builder.add(acc, term);
                }
                acc
            },
            Leaf::Challenge(index) => randomness::lower_challenge(builder, layout, index),
            Leaf::PermValue(index) => builder.input(InputKey::AuxBusBoundary(index)),
            Leaf::ExtConst([c0, c1]) => {
                let coeffs = [Felt::from_u64(c0), Felt::from_u64(c1)];
                let value = QuadFelt::from_basis_coefficients_slice(&coeffs)
                    .expect("two coefficients form a QuadFelt");
                builder.constant(value)
            },
            Leaf::ExtBase(inner) => lower_ir_expr(graph, inner, builder, layout, periodic_nodes),
        },
        Node::Op { op: OpKind::Neg, x, .. } => {
            let lx = lower_ir_expr(graph, x, builder, layout, periodic_nodes);
            builder.neg(lx)
        },
        Node::Op { op, x, y, .. } => {
            let lx = lower_ir_expr(graph, x, builder, layout, periodic_nodes);
            let y = y.expect("binary op has a right operand");
            let ly = lower_ir_expr(graph, y, builder, layout, periodic_nodes);
            match op {
                OpKind::Add => builder.add(lx, ly),
                OpKind::Sub => builder.sub(lx, ly),
                OpKind::Mul => builder.mul(lx, ly),
                OpKind::Neg => unreachable!("handled by the previous arm"),
            }
        },
    }
}
