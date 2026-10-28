use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::PrimeCharacteristicRing;

pub use crate::testing::eval_folded_constraints;
use crate::{
    InputLayout,
    dag::{NodeId, NodeKind},
};

pub fn eval_periodic_values(periodic_columns: &[Vec<Felt>], z_k: QuadFelt) -> Vec<QuadFelt> {
    crate::testing::eval_periodic_values::<Felt, QuadFelt>(periodic_columns, z_k)
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
    crate::testing::eval_quotient::<Felt, QuadFelt>(layout, inputs)
}
