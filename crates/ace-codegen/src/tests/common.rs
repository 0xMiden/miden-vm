#![allow(dead_code)]

use miden_core::{Felt, field::QuadFelt};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_miden_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};

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

pub fn input_key_for_symbolic<T>(var: &SymbolicVariable<T>) -> InputKey {
    match var.entry {
        Entry::Preprocessed { .. } => panic!("preprocessed not supported in test"),
        Entry::Main { offset } => InputKey::Main { offset, index: var.index },
        Entry::Permutation { .. } | Entry::Aux { .. } => {
            panic!("aux variables require coord merge in eval_expr");
        },
        Entry::Periodic => panic!("periodic variables are computed inside the circuit"),
        Entry::AuxBusBoundary => InputKey::AuxBusBoundary(var.index),
        Entry::Public => InputKey::Public(var.index),
        Entry::Challenge => {
            if var.index == 0 {
                InputKey::AuxRandAlpha
            } else if var.index == 1 {
                InputKey::AuxRandBeta
            } else {
                panic!("unsupported randomness index {0} in test", var.index)
            }
        },
    }
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

pub fn eval_expr(
    expr: &SymbolicExpression<QuadFelt>,
    inputs: &[QuadFelt],
    layout: &InputLayout,
    periodic_values: &[QuadFelt],
) -> QuadFelt {
    match expr {
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Aux { offset } | Entry::Permutation { offset } => {
                let mut acc = QuadFelt::ZERO;
                for coord in 0..layout.counts.ext_degree {
                    let basis =
                        <QuadFelt as BasedVectorSpace<Felt>>::ith_basis_element(coord).unwrap();
                    let key = InputKey::AuxCoord { offset, index: v.index, coord };
                    let value = inputs[layout.index(key).unwrap()];
                    acc += basis * value;
                }
                acc
            },
            Entry::Periodic => periodic_values[v.index],
            _ => {
                let key = input_key_for_symbolic(v);
                inputs[layout.index(key).unwrap()]
            },
        },
        SymbolicExpression::IsFirstRow => {
            let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
            let inv = inputs[layout.index(InputKey::InvZMinusOne).unwrap()];
            (z_pow_n - QuadFelt::ONE) * inv
        },
        SymbolicExpression::IsLastRow => {
            let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
            let inv = inputs[layout.index(InputKey::InvZMinusGInv).unwrap()];
            (z_pow_n - QuadFelt::ONE) * inv
        },
        SymbolicExpression::IsTransition => {
            let z = inputs[layout.index(InputKey::Z).unwrap()];
            let g_inv = inputs[layout.index(InputKey::GInv).unwrap()];
            z - g_inv
        },
        SymbolicExpression::Constant(c) => *c,
        SymbolicExpression::Add { x, y, .. } => {
            eval_expr(x, inputs, layout, periodic_values)
                + eval_expr(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Sub { x, y, .. } => {
            eval_expr(x, inputs, layout, periodic_values)
                - eval_expr(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Mul { x, y, .. } => {
            eval_expr(x, inputs, layout, periodic_values)
                * eval_expr(y, inputs, layout, periodic_values)
        },
        SymbolicExpression::Neg { x, .. } => -eval_expr(x, inputs, layout, periodic_values),
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
