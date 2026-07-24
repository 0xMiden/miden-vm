//! Symbolic-tree lowering to the verifier DAG — the differential anchor.
//!
//! This is the original lowering, superseded in production by the IR-driven
//! [`super::lower_ir`] (which documents the verifier expression both build). It
//! is compiled only for tests, where the node-for-node differential in
//! `miden-air` (`tests/ace_codegen.rs`) checks that the IR path replicates this
//! path's `DagBuilder` interning order exactly. Scheduled for deletion once the
//! migration has soaked; do not extend it.

use miden_crypto::{
    field::{ExtensionField, Field},
    stark::air::symbolic::{
        BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, ExtLeaf, SymbolicExpression,
        SymbolicExpressionExt,
    },
};

use super::{
    builder::DagBuilder,
    ir::{AceDag, NodeId, PeriodicColumnData},
    periodic::build_periodic_nodes,
};
use crate::{
    layout::{InputKey, InputLayout},
    quotient::build_quotient_recomposition_dag,
    randomness,
};

/// Lower a base-field symbolic expression into DAG nodes.
fn lower_base_expr<F, EF>(
    expr: &SymbolicExpression<F>,
    builder: &mut DagBuilder<EF>,
    periodic_nodes: &[NodeId],
) -> NodeId
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymbolicExpression::Leaf(leaf) => match leaf {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset } => {
                    builder.input(InputKey::Main { offset, index: v.index })
                },
                BaseEntry::Public => builder.input(InputKey::Public(v.index)),
                BaseEntry::Periodic => periodic_nodes
                    .get(v.index)
                    .copied()
                    .unwrap_or_else(|| panic!("periodic column index {} is out of range", v.index)),
                BaseEntry::Preprocessed { .. } => {
                    panic!("preprocessed trace entries are not supported")
                },
            },
            BaseLeaf::IsFirstRow => builder.input(InputKey::IsFirst),
            BaseLeaf::IsLastRow => builder.input(InputKey::IsLast),
            BaseLeaf::IsTransition => builder.input(InputKey::IsTransition),
            BaseLeaf::Constant(c) => builder.constant(EF::from(*c)),
        },
        SymbolicExpression::Add { x, y, .. } => {
            let lx = lower_base_expr::<F, EF>(x, builder, periodic_nodes);
            let ly = lower_base_expr::<F, EF>(y, builder, periodic_nodes);
            builder.add(lx, ly)
        },
        SymbolicExpression::Sub { x, y, .. } => {
            let lx = lower_base_expr::<F, EF>(x, builder, periodic_nodes);
            let ly = lower_base_expr::<F, EF>(y, builder, periodic_nodes);
            builder.sub(lx, ly)
        },
        SymbolicExpression::Mul { x, y, .. } => {
            let lx = lower_base_expr::<F, EF>(x, builder, periodic_nodes);
            let ly = lower_base_expr::<F, EF>(y, builder, periodic_nodes);
            builder.mul(lx, ly)
        },
        SymbolicExpression::Neg { x, .. } => {
            let lx = lower_base_expr::<F, EF>(x, builder, periodic_nodes);
            builder.neg(lx)
        },
    }
}

/// Lower an extension-field symbolic expression into DAG nodes.
fn lower_ext_expr<F, EF>(
    expr: &SymbolicExpressionExt<F, EF>,
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
    periodic_nodes: &[NodeId],
) -> NodeId
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymbolicExpressionExt::Leaf(leaf) => match leaf {
            ExtLeaf::Base(base_expr) => {
                lower_base_expr::<F, EF>(base_expr, builder, periodic_nodes)
            },
            ExtLeaf::ExtVariable(v) => match v.entry {
                ExtEntry::Permutation { offset } => {
                    let index = v.index;
                    let mut acc = builder.constant(EF::ZERO);
                    for coord in 0..EF::DIMENSION {
                        let basis = EF::ith_basis_element(coord)
                            .expect("basis index within extension degree");
                        let coord_node = builder.input(InputKey::AuxCoord { offset, index, coord });
                        let basis_node = builder.constant(basis);
                        let term = builder.mul(basis_node, coord_node);
                        acc = builder.add(acc, term);
                    }
                    acc
                },
                ExtEntry::Challenge => randomness::lower_challenge(builder, layout, v.index),
                ExtEntry::PermutationValue => builder.input(InputKey::AuxBusBoundary(v.index)),
            },
            ExtLeaf::ExtConstant(c) => builder.constant(*c),
        },
        SymbolicExpressionExt::Add { x, y, .. } => {
            let lx = lower_ext_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_ext_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.add(lx, ly)
        },
        SymbolicExpressionExt::Sub { x, y, .. } => {
            let lx = lower_ext_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_ext_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.sub(lx, ly)
        },
        SymbolicExpressionExt::Mul { x, y, .. } => {
            let lx = lower_ext_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_ext_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.mul(lx, ly)
        },
        SymbolicExpressionExt::Neg { x, .. } => {
            let lx = lower_ext_expr::<F, EF>(x, builder, layout, periodic_nodes);
            builder.neg(lx)
        },
    }
}

/// Build the verifier-equivalent root expression DAG.
///
/// This constructs the folded constraint accumulator, divides by the vanishing
/// polynomial, recomposes the quotient, and subtracts both sides to yield the
/// root expression evaluated by the ACE circuit.
pub fn build_verifier_dag<F, EF>(
    base_constraints: &[SymbolicExpression<F>],
    ext_constraints: &[SymbolicExpressionExt<F, EF>],
    constraint_layout: &ConstraintLayout,
    layout: &InputLayout,
    periodic: Option<&PeriodicColumnData<EF>>,
) -> AceDag<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let mut builder = DagBuilder::<EF>::new();
    let periodic_nodes = match periodic {
        Some(data) => build_periodic_nodes(&mut builder, layout, data),
        None => Vec::new(),
    };
    let alpha = builder.input(InputKey::Alpha);

    // Merge base and extension constraints in evaluation order using the layout.
    let total = constraint_layout.base_indices.len() + constraint_layout.ext_indices.len();
    let mut ordered: Vec<(usize, bool, usize)> = Vec::with_capacity(total);
    for (i, &pos) in constraint_layout.base_indices.iter().enumerate() {
        ordered.push((pos, false, i));
    }
    for (i, &pos) in constraint_layout.ext_indices.iter().enumerate() {
        ordered.push((pos, true, i));
    }
    ordered.sort_by_key(|(pos, ..)| *pos);

    let mut acc = builder.constant(EF::ZERO);
    for &(_, is_ext, idx) in &ordered {
        let node = if is_ext {
            lower_ext_expr::<F, EF>(&ext_constraints[idx], &mut builder, layout, &periodic_nodes)
        } else {
            lower_base_expr::<F, EF>(&base_constraints[idx], &mut builder, &periodic_nodes)
        };
        let acc_mul = builder.mul(acc, alpha);
        acc = builder.add(acc_mul, node);
    }

    let quotient = build_quotient_recomposition_dag::<F, EF>(&mut builder, layout);
    let z_pow_n = builder.input(InputKey::ZPowN);
    let one = builder.constant(EF::ONE);
    let vanishing = builder.sub(z_pow_n, one);
    let q_times_v = builder.mul(quotient, vanishing);
    let root = builder.sub(acc, q_times_v);

    let mut dag = builder.build(root);
    dag.compact();
    dag
}
