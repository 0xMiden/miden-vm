use std::collections::HashMap;

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
                BaseEntry::Periodic => periodic_nodes[v.index],
                BaseEntry::Preprocessed { .. } => {
                    panic!("preprocessed trace entries are not supported")
                },
            },
            BaseLeaf::IsFirstRow => {
                let z_pow_n = builder.input(InputKey::ZPowN);
                let one = builder.constant(EF::ONE);
                let numerator = builder.sub(z_pow_n, one);
                let inv = builder.input(InputKey::InvZMinusOne);
                builder.mul(numerator, inv)
            },
            BaseLeaf::IsLastRow => {
                let z_pow_n = builder.input(InputKey::ZPowN);
                let one = builder.constant(EF::ONE);
                let numerator = builder.sub(z_pow_n, one);
                let inv = builder.input(InputKey::InvZMinusGInv);
                builder.mul(numerator, inv)
            },
            BaseLeaf::IsTransition => {
                let z = builder.input(InputKey::Z);
                let g_inv = builder.input(InputKey::GInv);
                builder.sub(z, g_inv)
            },
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
        Some(data) => {
            assert_eq!(
                data.num_columns(),
                layout.counts.num_periodic,
                "periodic column count mismatch"
            );
            build_periodic_nodes(&mut builder, layout, data)
        },
        None => Vec::new(),
    };
    let alpha = builder.input(InputKey::Alpha);
    let inv_vanishing = builder.input(InputKey::InvVanishing);

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
    let folded = builder.mul(acc, inv_vanishing);

    let quotient = build_quotient_recomposition_dag::<F, EF>(&mut builder, layout);
    let root = builder.sub(folded, quotient);

    AceDag { nodes: builder.into_nodes(), root }
}

fn build_periodic_nodes<EF>(
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
    periodic: &PeriodicColumnData<EF>,
) -> Vec<NodeId>
where
    EF: Field,
{
    if periodic.num_columns() == 0 {
        return Vec::new();
    }

    assert!(
        layout.index(InputKey::ZK).is_some(),
        "layout must include ZK for periodic columns"
    );

    let max_len = periodic.max_period();
    let mut cache = HashMap::<u32, NodeId>::new();
    let mut nodes = Vec::with_capacity(periodic.num_columns());
    for coeffs in periodic.columns() {
        let col_len = coeffs.len();
        let ratio = max_len / col_len;
        let log_pow_col = ratio.ilog2();
        let z_col = *cache.entry(log_pow_col).or_insert_with(|| {
            let mut z_col = builder.input(InputKey::ZK);
            for _ in 0..log_pow_col {
                z_col = builder.mul(z_col, z_col);
            }
            z_col
        });

        let coeff_nodes: Vec<NodeId> = coeffs.iter().map(|c| builder.constant(*c)).collect();
        let value = horner_eval(builder, z_col, &coeff_nodes);
        nodes.push(value);
    }
    nodes
}

fn horner_eval<EF>(builder: &mut DagBuilder<EF>, point: NodeId, coeffs: &[NodeId]) -> NodeId
where
    EF: Field,
{
    let mut acc = builder.constant(EF::ZERO);
    for coeff in coeffs.iter().rev() {
        let mul = builder.mul(point, acc);
        acc = builder.add(*coeff, mul);
    }
    acc
}
