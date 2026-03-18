//! Lowering from symbolic AIR constraints to the verifier DAG.
//!
//! # Verifier expression
//!
//! The ACE circuit evaluates the STARK verifier's core check at a single
//! out-of-domain point `z`. The root expression is:
//!
//! ```text
//!   root = acc - quotient_recomposition * (z^N - 1)
//! ```
//!
//! The verifier accepts if and only if `root == 0`.
//!
//! ## Constraint folding
//!
//! Given N constraints `C_0, C_1, ..., C_{N-1}`, the folded accumulator `acc`
//! is built via Horner's method with the composition challenge `alpha`:
//!
//! ```text
//!   acc = C_0 + alpha * (C_1 + alpha * (C_2 + ... ))
//! ```
//!
//! Each constraint `C_i(z)` is a symbolic expression over trace openings,
//! public inputs, periodic columns, and selector polynomials (see below).
//!
//!
//! ## Selector polynomials
//!
//! Constraints may be multiplied by selector polynomials that restrict them
//! to specific rows. These selectors are precomputed by the MASM verifier
//! and supplied as circuit inputs:
//!
//! - `is_first = (z^N - 1) / (z - 1)` Active on the first row of the trace.
//!
//! - `is_last = (z^N - 1) / (z - g^{-1})` Active on the last row of the trace (g = trace domain
//!   generator).
//!
//! - `is_transition = z - g^{-1}` Active on all rows except the last.
//!
//! ## Periodic columns
//!
//! Periodic columns are polynomials evaluated at `z_k = z^(N / max_cycle_len)`.
//! Each column's coefficients are Horner-evaluated at `z_k` (or a power of
//! `z_k` for columns whose period divides `max_cycle_len`).
//!
//! ## Quotient recomposition
//!
//! The quotient polynomial `Q(x)` is split into `k` chunks `Q_0, ..., Q_{k-1}`,
//! where chunk `Q_i` is evaluated on a coset shifted by `s_i`. To recover the
//! combined quotient at `z^N`, barycentric interpolation over the `k` coset
//! shifts is used:
//!
//! ```text
//!   s_i      = s0 * f^i              (coset shifts)
//!   delta_i  = z^N - s_i             (eval point minus each shift)
//!   w_i      = weight0 * f^i         (barycentric weights)
//!   zps_i    = w_i * prod_{j != i} delta_j
//!
//!   quotient_recomposition = sum_{i=0}^{k-1} zps_i * Q_i(z)
//! ```
//!
//! where `s0 = offset^N`, `f = h^N` (h = LDE domain generator),
//! `weight0 = 1 / (k * s0^{k-1})`, and `Q_i(z)` is reconstructed from its
//! base-field coordinates evaluations.
//!
//! ## Stark variables summary
//!
//! Each stark variable and where it enters the expression:
//!
//! ```text
//!   alpha          Composition challenge. Horner accumulator for constraint folding.
//!   z^N            Trace-length power. Vanishing factor and delta base in quotient
//!                  recomposition.
//!   z_k            Periodic column evaluation point (z^(N / max_cycle_len)).
//!   is_first       Precomputed selector (z^N - 1) / (z - 1).
//!   is_last        Precomputed selector (z^N - 1) / (z - g^{-1}).
//!   is_transition  Precomputed selector z - g^{-1}.
//!   gamma          Batching challenge for auxiliary trace boundary checks.
//!   weight0        First barycentric weight for quotient recomposition.
//!   f              Chunk shift ratio h^N. Generates coset shifts and weights.
//!   s0             First coset shift offset^N. Base for shifted evaluation points.
//! ```

use std::collections::HashMap;

use miden_crypto::field::{ExtensionField, Field};

use super::{
    builder::DagBuilder,
    ir::{AceDag, NodeId, PeriodicColumnData},
};
use crate::{
    layout::{InputKey, InputLayout},
    quotient::build_quotient_recomposition_dag,
    randomness,
    symbolic::{Entry, SymExpr},
};

/// Lower a symbolic expression into DAG nodes using the provided layout.
pub fn lower_expr<F, EF>(
    expr: &SymExpr<EF>,
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
    periodic_nodes: &[NodeId],
) -> NodeId
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymExpr::Variable(v) => match v.entry {
            Entry::Challenge => randomness::lower_challenge(builder, layout, v.index),
            Entry::Aux { offset } => {
                let index = v.index;
                let mut acc = builder.constant(EF::ZERO);
                for coord in 0..EF::DIMENSION {
                    let basis =
                        EF::ith_basis_element(coord).expect("basis index within extension degree");
                    let coord_node = builder.input(InputKey::AuxCoord { offset, index, coord });
                    let basis_node = builder.constant(basis);
                    let term = builder.mul(basis_node, coord_node);
                    acc = builder.add(acc, term);
                }
                acc
            },
            Entry::Periodic => periodic_nodes[v.index],
            Entry::Main { offset } => builder.input(InputKey::Main { offset, index: v.index }),
            Entry::AuxBusBoundary => builder.input(InputKey::AuxBusBoundary(v.index)),
            Entry::Public => builder.input(InputKey::Public(v.index)),
            Entry::Preprocessed { .. } => {
                panic!("preprocessed trace entries are not supported")
            },
        },
        SymExpr::IsFirstRow => builder.input(InputKey::IsFirst),
        SymExpr::IsLastRow => builder.input(InputKey::IsLast),
        SymExpr::IsTransition => builder.input(InputKey::IsTransition),
        SymExpr::Constant(c) => builder.constant(*c),
        SymExpr::Add(x, y) => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.add(lx, ly)
        },
        SymExpr::Sub(x, y) => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.sub(lx, ly)
        },
        SymExpr::Mul(x, y) => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes);
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes);
            builder.mul(lx, ly)
        },
        SymExpr::Neg(x) => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes);
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
    constraints: &[SymExpr<EF>],
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

    let mut acc = builder.constant(EF::ZERO);
    for constraint in constraints {
        let node = lower_expr::<F, EF>(constraint, &mut builder, layout, &periodic_nodes);
        let acc_mul = builder.mul(acc, alpha);
        acc = builder.add(acc_mul, node);
    }

    let quotient = build_quotient_recomposition_dag::<F, EF>(&mut builder, layout);
    let z_pow_n = builder.input(InputKey::ZPowN);
    let one = builder.constant(EF::ONE);
    let vanishing = builder.sub(z_pow_n, one);
    let q_times_v = builder.mul(quotient, vanishing);
    let root = builder.sub(acc, q_times_v);

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
