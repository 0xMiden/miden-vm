//! Periodic-column evaluation nodes, shared by both lowerings.
//!
//! Each column is emitted in its preselected representation: dense monomial
//! coefficients via Horner evaluation, or sparse Lagrange form over nonzero
//! evaluations.

use std::collections::HashMap;

use miden_crypto::field::Field;

use super::{
    builder::DagBuilder,
    ir::{NodeId, PeriodicColumn, PeriodicColumnData, SparseTerm},
};
use crate::layout::{InputKey, InputLayout};

pub(super) fn build_periodic_nodes<EF>(
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
    let mut z_cache = HashMap::<u32, NodeId>::new();
    let mut zpow_cache = HashMap::<u32, Vec<NodeId>>::new();
    let mut nodes = Vec::with_capacity(periodic.num_columns());
    for column in periodic.columns() {
        let col_len = column.period();
        let ratio = max_len / col_len;
        let log_pow_col = ratio.ilog2();
        let log_len = col_len.ilog2();

        let value = match column {
            PeriodicColumn::Sparse { terms, .. } => {
                let zpow = zpow_cache.entry(log_pow_col).or_insert_with(|| {
                    let mut z_col = builder.input(InputKey::ZK);
                    for _ in 0..log_pow_col {
                        z_col = builder.mul(z_col, z_col);
                    }
                    let mut powers = Vec::with_capacity(log_len as usize);
                    let mut p = z_col;
                    for _ in 0..log_len {
                        powers.push(p);
                        p = builder.mul(p, p);
                    }
                    powers
                });
                build_sparse_periodic_value(builder, zpow, terms)
            },
            PeriodicColumn::Dense(coeffs) => {
                let z_col = *z_cache.entry(log_pow_col).or_insert_with(|| {
                    let mut z_col = builder.input(InputKey::ZK);
                    for _ in 0..log_pow_col {
                        z_col = builder.mul(z_col, z_col);
                    }
                    z_col
                });
                let coeff_nodes: Vec<NodeId> =
                    coeffs.iter().map(|c| builder.constant(*c)).collect();
                horner_eval(builder, z_col, &coeff_nodes)
            },
        };
        nodes.push(value);
    }
    nodes
}

/// Evaluate a periodic column's Lagrange form at the cached doubling powers of its
/// evaluation point, summing only the nonzero-value terms.
fn build_sparse_periodic_value<EF>(
    builder: &mut DagBuilder<EF>,
    zpow: &[NodeId],
    terms: &[SparseTerm<EF>],
) -> NodeId
where
    EF: Field,
{
    if terms.is_empty() {
        return builder.constant(EF::ZERO);
    }

    let mut sum: Option<NodeId> = None;
    for term in terms {
        let mut factor = builder.constant(EF::ONE);
        for (&power, &twiddle) in zpow.iter().zip(&term.twiddles) {
            let twiddle_node = builder.constant(twiddle);
            let scaled_pow = builder.mul(twiddle_node, power);
            let one = builder.constant(EF::ONE);
            let one_plus = builder.add(one, scaled_pow);
            factor = builder.mul(factor, one_plus);
        }
        let value_node = builder.constant(term.scaled_value);
        let contribution = builder.mul(value_node, factor);
        sum = Some(match sum {
            None => contribution,
            Some(acc) => builder.add(acc, contribution),
        });
    }
    sum.expect("terms is non-empty")
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
