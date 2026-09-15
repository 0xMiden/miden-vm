use miden_core::{Felt, field::QuadFelt};

use crate::InputLayout;
pub use crate::testing::{eval_dag, eval_folded_constraints};

pub fn eval_periodic_values(periodic_columns: &[Vec<Felt>], z_k: QuadFelt) -> Vec<QuadFelt> {
    crate::testing::eval_periodic_values::<Felt, QuadFelt>(periodic_columns, z_k)
}

pub fn eval_quotient(layout: &InputLayout, inputs: &[QuadFelt]) -> QuadFelt {
    crate::testing::eval_quotient::<Felt, QuadFelt>(layout, inputs)
}
