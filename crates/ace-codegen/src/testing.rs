//! Test helpers for ACE codegen, available under the `testing` feature or `#[cfg(test)]`.
//!
//! These provide reference evaluators for symbolic expressions, periodic columns,
//! constraint folding, quotient recomposition, and DAG evaluation, suitable for
//! validating the ACE pipeline from both within ace-codegen tests and from
//! downstream integration tests (e.g. in miden-air).

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{ExtensionField, Field, TwoAdicField},
    stark::{
        air::symbolic::{
            BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, ExtLeaf, SymbolicExpression,
            SymbolicExpressionExt,
        },
        dft::{Radix2DitParallel, TwoAdicSubgroupDft},
    },
};

use crate::{AceDag, AceError, InputKey, InputLayout};

/// Deterministic input filler for layout-sized buffers.
///
/// Generates pseudo-random `QuadFelt` values using a simple LCG, suitable for
/// testing against hand-computed reference values.
pub fn fill_inputs(layout: &InputLayout) -> Vec<QuadFelt> {
    let mut values = Vec::with_capacity(layout.total_inputs);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..layout.total_inputs {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let lo = Felt::new(state);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let hi = Felt::new(state);
        values.push(QuadFelt::new([lo, hi]));
    }
    values
}

/// Evaluate periodic columns at a point by computing the polynomial in
/// coefficient form via inverse DFT, then evaluating with Horner's method.
pub fn eval_periodic_values<F, EF>(periodic_columns: &[Vec<F>], z_k: EF) -> Vec<EF>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F>,
{
    if periodic_columns.is_empty() {
        return Vec::new();
    }
    let max_len = periodic_columns.iter().map(Vec::len).max().unwrap_or(0);
    let dft = Radix2DitParallel::<F>::default();

    periodic_columns
        .iter()
        .map(|col| {
            if col.is_empty() {
                return EF::ZERO;
            }
            let coeffs = dft.idft(col.clone());
            let ratio = max_len / col.len();
            let log_pow = ratio.ilog2() as usize;
            let mut z_col = z_k;
            for _ in 0..log_pow {
                z_col *= z_col;
            }
            let mut acc = EF::ZERO;
            for coeff in coeffs.iter().rev() {
                acc = acc * z_col + EF::from(*coeff);
            }
            acc
        })
        .collect()
}

/// Evaluate a base-field symbolic expression at concrete inputs.
pub fn eval_base_expr<F, EF>(
    expr: &SymbolicExpression<F>,
    inputs: &[EF],
    layout: &InputLayout,
    periodic_values: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymbolicExpression::Leaf(leaf) => match leaf {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset } => {
                    let key = InputKey::Main { offset, index: v.index };
                    inputs[layout.index(key).unwrap()]
                },
                BaseEntry::Public => {
                    let key = InputKey::Public(v.index);
                    inputs[layout.index(key).unwrap()]
                },
                BaseEntry::Periodic => periodic_values[v.index],
                BaseEntry::Preprocessed { .. } => panic!("preprocessed not supported in test"),
            },
            BaseLeaf::IsFirstRow => inputs[layout.index(InputKey::IsFirst).unwrap()],
            BaseLeaf::IsLastRow => inputs[layout.index(InputKey::IsLast).unwrap()],
            BaseLeaf::IsTransition => inputs[layout.index(InputKey::IsTransition).unwrap()],
            BaseLeaf::Constant(c) => EF::from(*c),
        },
        SymbolicExpression::Add { x, y, .. } => {
            eval_base_expr::<F, EF>(x, inputs, layout, periodic_values)
                + eval_base_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Sub { x, y, .. } => {
            eval_base_expr::<F, EF>(x, inputs, layout, periodic_values)
                - eval_base_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Mul { x, y, .. } => {
            eval_base_expr::<F, EF>(x, inputs, layout, periodic_values)
                * eval_base_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Neg { x, .. } => {
            -eval_base_expr::<F, EF>(x, inputs, layout, periodic_values)
        },
    }
}

/// Evaluate an extension-field symbolic expression at concrete inputs.
pub fn eval_ext_expr<F, EF>(
    expr: &SymbolicExpressionExt<F, EF>,
    inputs: &[EF],
    layout: &InputLayout,
    periodic_values: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymbolicExpressionExt::Leaf(leaf) => match leaf {
            ExtLeaf::Base(base_expr) => {
                eval_base_expr::<F, EF>(base_expr, inputs, layout, periodic_values)
            },
            ExtLeaf::ExtVariable(v) => match v.entry {
                ExtEntry::Permutation { offset } => {
                    let mut acc = EF::ZERO;
                    for coord in 0..EF::DIMENSION {
                        let basis = EF::ith_basis_element(coord).unwrap();
                        let key = InputKey::AuxCoord { offset, index: v.index, coord };
                        let value = inputs[layout.index(key).unwrap()];
                        acc += basis * value;
                    }
                    acc
                },
                ExtEntry::Challenge => {
                    let alpha = inputs[layout.index(InputKey::AuxRandAlpha).unwrap()];
                    let beta = inputs[layout.index(InputKey::AuxRandBeta).unwrap()];
                    match v.index {
                        0 => alpha,
                        1 => beta,
                        _ => panic!(
                            "challenge index {} exceeds the 2-element randomness convention",
                            v.index
                        ),
                    }
                },
                ExtEntry::PermutationValue => {
                    let key = InputKey::AuxBusBoundary(v.index);
                    inputs[layout.index(key).unwrap()]
                },
            },
            ExtLeaf::ExtConstant(c) => *c,
        },
        SymbolicExpressionExt::Add { x, y, .. } => {
            eval_ext_expr::<F, EF>(x, inputs, layout, periodic_values)
                + eval_ext_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpressionExt::Sub { x, y, .. } => {
            eval_ext_expr::<F, EF>(x, inputs, layout, periodic_values)
                - eval_ext_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpressionExt::Mul { x, y, .. } => {
            eval_ext_expr::<F, EF>(x, inputs, layout, periodic_values)
                * eval_ext_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymbolicExpressionExt::Neg { x, .. } => {
            -eval_ext_expr::<F, EF>(x, inputs, layout, periodic_values)
        },
    }
}

/// Evaluate the folded constraint accumulator from symbolic constraints.
///
/// Merges base and extension constraints in evaluation order (using the
/// `ConstraintLayout`), then folds them via Horner with `alpha`.
pub fn eval_folded_constraints<F, EF>(
    base_constraints: &[SymbolicExpression<F>],
    ext_constraints: &[SymbolicExpressionExt<F, EF>],
    constraint_layout: &ConstraintLayout,
    inputs: &[EF],
    layout: &InputLayout,
    periodic_values: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let alpha = inputs[layout.index(InputKey::Alpha).unwrap()];

    let total = constraint_layout.base_indices.len() + constraint_layout.ext_indices.len();
    let mut ordered: Vec<(usize, bool, usize)> = Vec::with_capacity(total);
    for (i, &pos) in constraint_layout.base_indices.iter().enumerate() {
        ordered.push((pos, false, i));
    }
    for (i, &pos) in constraint_layout.ext_indices.iter().enumerate() {
        ordered.push((pos, true, i));
    }
    ordered.sort_by_key(|(pos, ..)| *pos);

    let mut acc = EF::ZERO;
    for &(_, is_ext, idx) in &ordered {
        let val = if is_ext {
            eval_ext_expr::<F, EF>(&ext_constraints[idx], inputs, layout, periodic_values)
        } else {
            eval_base_expr::<F, EF>(&base_constraints[idx], inputs, layout, periodic_values)
        };
        acc = acc * alpha + val;
    }
    acc
}

/// Evaluate the quotient recomposition at `zeta` using provided inputs.
pub fn eval_quotient<F, EF>(layout: &InputLayout, inputs: &[EF]) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let k = layout.counts.num_quotient_chunks;
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
    let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
    let f = inputs[layout.index(InputKey::F).expect("F in layout")];
    let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

    let (deltas, weights) = compute_deltas_and_weights(k, z_pow_n, s0, f, weight0);

    let mut quotient = EF::ZERO;
    for chunk in 0..k {
        let mut chunk_value = EF::ZERO;
        for coord in 0..EF::DIMENSION {
            let basis = EF::ith_basis_element(coord).expect("basis index within extension degree");
            let coord_value = inputs[layout
                .index(InputKey::QuotientChunkCoord { offset: 0, chunk, coord })
                .expect("quotient chunk coord in layout")];
            chunk_value += basis * coord_value;
        }

        let mut prod = EF::ONE;
        for (j, delta) in deltas.iter().enumerate() {
            if j != chunk {
                prod *= *delta;
            }
        }
        quotient += weights[chunk] * prod * chunk_value;
    }

    quotient
}

/// Compute the barycentric kernel value (`zps`) for a single quotient chunk.
pub fn zps_for_chunk<F, EF>(layout: &InputLayout, inputs: &[EF], chunk: usize) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let k = layout.counts.num_quotient_chunks;
    assert!(chunk < k, "quotient chunk {chunk} out of range (k={k})");

    let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
    let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
    let f = inputs[layout.index(InputKey::F).expect("F in layout")];
    let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

    let (deltas, weights) = compute_deltas_and_weights(k, z_pow_n, s0, f, weight0);

    let mut prod = EF::ONE;
    for (j, delta) in deltas.iter().enumerate() {
        if j != chunk {
            prod *= *delta;
        }
    }

    weights[chunk] * prod
}

/// Evaluate a lowered DAG against concrete inputs.
pub fn eval_dag<EF>(dag: &AceDag<EF>, inputs: &[EF], layout: &InputLayout) -> Result<EF, AceError>
where
    EF: Field,
{
    if inputs.len() != layout.total_inputs {
        return Err(AceError::InvalidInputLength {
            expected: layout.total_inputs,
            got: inputs.len(),
        });
    }

    let mut values: Vec<EF> = vec![EF::ZERO; dag.nodes().len()];
    for (idx, node) in dag.nodes().iter().enumerate() {
        let value = match node {
            crate::dag::NodeKind::Input(key) => {
                let input_idx = layout.index(*key).ok_or_else(|| AceError::InvalidInputLayout {
                    message: format!("missing input key in layout: {key:?}"),
                })?;
                inputs[input_idx]
            },
            crate::dag::NodeKind::Constant(c) => *c,
            crate::dag::NodeKind::Add(a, b) => values[a.index()] + values[b.index()],
            crate::dag::NodeKind::Sub(a, b) => values[a.index()] - values[b.index()],
            crate::dag::NodeKind::Mul(a, b) => values[a.index()] * values[b.index()],
            crate::dag::NodeKind::Neg(a) => -values[a.index()],
        };
        values[idx] = value;
    }

    Ok(values[dag.root().index()])
}

fn compute_deltas_and_weights<EF: Field>(
    k: usize,
    z_pow_n: EF,
    s0: EF,
    f: EF,
    weight0: EF,
) -> (Vec<EF>, Vec<EF>) {
    let mut deltas = Vec::with_capacity(k);
    let mut weights = Vec::with_capacity(k);
    let mut shift = s0;
    let mut weight = weight0;
    for _ in 0..k {
        deltas.push(z_pow_n - shift);
        weights.push(weight);
        shift *= f;
        weight *= f;
    }
    (deltas, weights)
}
