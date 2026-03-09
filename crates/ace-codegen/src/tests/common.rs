use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{ExtensionField, Field, PrimeCharacteristicRing},
    stark::{
        air::symbolic::{
            BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, ExtLeaf, SymbolicExpression,
            SymbolicExpressionExt,
        },
        dft::{Radix2DitParallel, TwoAdicSubgroupDft},
    },
};

use crate::{
    InputKey, InputLayout,
    dag::{NodeId, NodeKind},
    quotient,
};

/// Deterministic input filler for layout-sized buffers.
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

pub fn eval_periodic_values(periodic_columns: &[Vec<Felt>], z_k: QuadFelt) -> Vec<QuadFelt> {
    if periodic_columns.is_empty() {
        return Vec::new();
    }
    let max_len = periodic_columns.iter().map(|col| col.len()).max().unwrap_or(0);
    let dft = Radix2DitParallel::<Felt>::default();

    periodic_columns
        .iter()
        .map(|col| {
            if col.is_empty() {
                return QuadFelt::ZERO;
            }
            let coeffs = dft.idft(col.clone());
            let ratio = max_len / col.len();
            let log_pow = ratio.ilog2() as usize;
            let mut z_col = z_k;
            for _ in 0..log_pow {
                z_col *= z_col;
            }
            let mut acc = QuadFelt::ZERO;
            for coeff in coeffs.iter().rev() {
                acc = acc * z_col + QuadFelt::from(*coeff);
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
                BaseEntry::Preprocessed { .. } => {
                    panic!("preprocessed not supported in test")
                },
            },
            BaseLeaf::IsFirstRow => {
                let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
                let inv = inputs[layout.index(InputKey::InvZMinusOne).unwrap()];
                (z_pow_n - EF::ONE) * inv
            },
            BaseLeaf::IsLastRow => {
                let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
                let inv = inputs[layout.index(InputKey::InvZMinusGInv).unwrap()];
                (z_pow_n - EF::ONE) * inv
            },
            BaseLeaf::IsTransition => {
                let z = inputs[layout.index(InputKey::Z).unwrap()];
                let g_inv = inputs[layout.index(InputKey::GInv).unwrap()];
                z - g_inv
            },
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
                        1 => EF::ONE,
                        _ => {
                            let mut power = beta;
                            for _ in 2..v.index {
                                power *= beta;
                            }
                            power
                        },
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

/// Evaluate all constraints (base + extension) folded with alpha in evaluation order.
pub fn eval_folded_constraints<F, EF>(
    base_constraints: &[SymbolicExpression<F>],
    ext_constraints: &[SymbolicExpressionExt<F, EF>],
    constraint_layout: &ConstraintLayout,
    alpha: EF,
    inputs: &[EF],
    layout: &InputLayout,
    periodic_values: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
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

pub fn eval_dag(
    nodes: &[NodeKind<QuadFelt>],
    root: NodeId,
    inputs: &[QuadFelt],
    layout: &InputLayout,
) -> QuadFelt {
    let mut values: Vec<QuadFelt> = vec![QuadFelt::ZERO; nodes.len()];
    for (idx, node) in nodes.iter().enumerate() {
        let v = match node {
            NodeKind::Input(key) => inputs[layout.index(*key).unwrap()],
            NodeKind::Constant(c) => *c,
            NodeKind::Add(a, b) => values[a.index()] + values[b.index()],
            NodeKind::Sub(a, b) => values[a.index()] - values[b.index()],
            NodeKind::Mul(a, b) => values[a.index()] * values[b.index()],
            NodeKind::Neg(a) => -values[a.index()],
        };
        values[idx] = v;
    }
    values[root.index()]
}

pub fn eval_quotient(layout: &InputLayout, inputs: &[QuadFelt]) -> QuadFelt {
    quotient::eval_quotient::<Felt, QuadFelt>(layout, inputs).expect("quotient evaluation")
}

pub fn zps_for_chunk(layout: &InputLayout, inputs: &[QuadFelt], chunk: usize) -> QuadFelt {
    quotient::zps_for_chunk(layout, inputs, chunk).expect("quotient zps")
}
