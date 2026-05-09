//! Quotient recomposition helpers shared by the DAG builder and tests.
//!
//! These routines mirror the verifier's barycentric recomposition of quotient
//! chunks. They are intentionally centralized to keep DAG lowering and tests
//! aligned.

use miden_crypto::field::{ExtensionField, Field};

use crate::{
    dag::{DagBuilder, NodeId},
    layout::{InputKey, InputLayout},
};

/// Build DAG nodes that recombine quotient chunks.
pub(crate) fn build_quotient_recomposition_dag<F, EF>(
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
) -> NodeId
where
    F: Field,
    EF: ExtensionField<F>,
{
    let k = layout.counts.num_quotient_chunks;
    let z_pow_n = builder.input(InputKey::ZPowN);
    let s0 = builder.input(InputKey::S0);
    let f = builder.input(InputKey::F);
    let weight0 = builder.input(InputKey::Weight0);

    let (deltas, weights) = {
        let mut ops = DagOps { builder };
        compute_deltas_and_weights(k, z_pow_n, s0, f, weight0, &mut ops)
    };

    let mut chunk_values = Vec::with_capacity(k);
    for chunk in 0..k {
        let mut value = builder.constant(EF::ZERO);
        for coord in 0..EF::DIMENSION {
            let basis = EF::ith_basis_element(coord).expect("basis index within extension degree");
            let coord_node =
                builder.input(InputKey::QuotientChunkCoord { offset: 0, chunk, coord });
            let basis_node = builder.constant(basis);
            let term = builder.mul(basis_node, coord_node);
            value = builder.add(value, term);
        }
        chunk_values.push(value);
    }

    let mut quotient = builder.constant(EF::ZERO);
    for (i, &chunk_value) in chunk_values.iter().enumerate() {
        let mut prod = builder.constant(EF::ONE);
        for (j, delta) in deltas.iter().enumerate() {
            if i != j {
                prod = builder.mul(prod, *delta);
            }
        }
        let zps = builder.mul(weights[i], prod);
        let term = builder.mul(zps, chunk_value);
        quotient = builder.add(quotient, term);
    }

    quotient
}

struct DagOps<'a, EF> {
    builder: &'a mut DagBuilder<EF>,
}

impl<'a, EF> Ops<NodeId> for DagOps<'a, EF>
where
    EF: Field,
{
    fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.builder.sub(a, b)
    }

    fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.builder.mul(a, b)
    }
}

trait Ops<T> {
    fn sub(&mut self, a: T, b: T) -> T;
    fn mul(&mut self, a: T, b: T) -> T;
}

fn compute_deltas_and_weights<T>(
    k: usize,
    z_pow_n: T,
    s0: T,
    f: T,
    weight0: T,
    ops: &mut impl Ops<T>,
) -> (Vec<T>, Vec<T>)
where
    T: Copy,
{
    let mut deltas = Vec::with_capacity(k);
    let mut weights = Vec::with_capacity(k);
    let mut shift = s0;
    let mut weight = weight0;
    for _ in 0..k {
        deltas.push(ops.sub(z_pow_n, shift));
        weights.push(weight);
        shift = ops.mul(shift, f);
        weight = ops.mul(weight, f);
    }
    (deltas, weights)
}
