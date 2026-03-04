use miden_core::{Felt, field::QuadFelt};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use crate::{
    InputKey, InputLayout,
    dag::{NodeId, NodeKind},
    quotient,
    symbolic::{Entry, SymExpr},
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

pub fn eval_periodic_values(periodic_table: &[Vec<Felt>], z_k: QuadFelt) -> Vec<QuadFelt> {
    if periodic_table.is_empty() {
        return Vec::new();
    }
    let max_len = periodic_table.iter().map(|col| col.len()).max().unwrap_or(0);
    let dft = Radix2DitParallel::<Felt>::default();

    periodic_table
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

pub fn eval_expr<F, EF>(
    expr: &SymExpr<EF>,
    inputs: &[EF],
    layout: &InputLayout,
    periodic_values: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    match expr {
        SymExpr::Variable(v) => match v.entry {
            Entry::Aux { offset } => {
                let mut acc = EF::ZERO;
                for coord in 0..EF::DIMENSION {
                    let basis = EF::ith_basis_element(coord).unwrap();
                    let key = InputKey::AuxCoord { offset, index: v.index, coord };
                    let value = inputs[layout.index(key).unwrap()];
                    acc += basis * value;
                }
                acc
            },
            Entry::Challenge => {
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
            Entry::Periodic => periodic_values[v.index],
            Entry::Main { offset } => {
                let key = InputKey::Main { offset, index: v.index };
                inputs[layout.index(key).unwrap()]
            },
            Entry::AuxBusBoundary => {
                let key = InputKey::AuxBusBoundary(v.index);
                inputs[layout.index(key).unwrap()]
            },
            Entry::Public => {
                let key = InputKey::Public(v.index);
                inputs[layout.index(key).unwrap()]
            },
            Entry::Preprocessed { .. } => {
                panic!("preprocessed not supported in test")
            },
        },
        SymExpr::IsFirstRow => {
            let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
            let inv = inputs[layout.index(InputKey::InvZMinusOne).unwrap()];
            (z_pow_n - EF::ONE) * inv
        },
        SymExpr::IsLastRow => {
            let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
            let inv = inputs[layout.index(InputKey::InvZMinusGInv).unwrap()];
            (z_pow_n - EF::ONE) * inv
        },
        SymExpr::IsTransition => {
            let z = inputs[layout.index(InputKey::Z).unwrap()];
            let g_inv = inputs[layout.index(InputKey::GInv).unwrap()];
            z - g_inv
        },
        SymExpr::Constant(c) => *c,
        SymExpr::Add(x, y) => {
            eval_expr::<F, EF>(x, inputs, layout, periodic_values)
                + eval_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymExpr::Sub(x, y) => {
            eval_expr::<F, EF>(x, inputs, layout, periodic_values)
                - eval_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymExpr::Mul(x, y) => {
            eval_expr::<F, EF>(x, inputs, layout, periodic_values)
                * eval_expr::<F, EF>(y, inputs, layout, periodic_values)
        },
        SymExpr::Neg(x) => -eval_expr::<F, EF>(x, inputs, layout, periodic_values),
    }
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
