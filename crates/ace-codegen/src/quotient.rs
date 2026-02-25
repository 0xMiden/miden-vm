//! Quotient recomposition helpers shared by the DAG builder and tests.
//!
//! These routines mirror the verifier's barycentric recomposition of quotient
//! chunks. They are intentionally centralized to keep DAG lowering and tests
//! aligned.

use core::hash::Hash;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use crate::{
    AceError,
    dag::{DagBuilder, NodeId},
    layout::{InputKey, InputLayout},
};

/// Evaluate the quotient recomposition at `zeta` using provided inputs.
#[cfg(test)]
pub fn eval_quotient<F, EF>(layout: &InputLayout, inputs: &[EF]) -> Result<EF, AceError>
where
    F: PrimeCharacteristicRing,
    EF: PrimeCharacteristicRing + BasedVectorSpace<F> + Copy,
{
    ensure_input_len(layout, inputs)?;

    let k = layout.counts.num_quotient_chunks;
    let d = layout.counts.ext_degree;
    let z_pow_n = input_value(layout, inputs, InputKey::ZPowN)?;
    let s0 = input_value(layout, inputs, InputKey::S0)?;
    let g = input_value(layout, inputs, InputKey::G)?;
    let weight0 = input_value(layout, inputs, InputKey::Weight0)?;

    let (deltas, weights) = {
        let mut ops = FieldOps;
        compute_deltas_and_weights(k, z_pow_n, s0, g, weight0, &mut ops)
    };

    let mut chunk_values = Vec::with_capacity(k);
    for chunk in 0..k {
        let mut value = EF::ZERO;
        for coord in 0..d {
            let basis = EF::ith_basis_element(coord).ok_or(AceError::InvalidBasisIndex(coord))?;
            let coord_value = input_value(
                layout,
                inputs,
                InputKey::QuotientChunkCoord { offset: 0, chunk, coord },
            )?;
            value += basis * coord_value;
        }
        chunk_values.push(value);
    }

    let mut quotient = EF::ZERO;
    for (i, &chunk_value) in chunk_values.iter().enumerate() {
        let mut prod = EF::ONE;
        for (j, delta) in deltas.iter().enumerate() {
            if i != j {
                prod *= *delta;
            }
        }
        let zps = weights[i] * prod;
        quotient += zps * chunk_value;
    }

    Ok(quotient)
}

/// Compute the barycentric kernel value (`zps`) for a single chunk.
#[cfg(test)]
pub fn zps_for_chunk<EF>(layout: &InputLayout, inputs: &[EF], chunk: usize) -> Result<EF, AceError>
where
    EF: PrimeCharacteristicRing + Copy,
{
    ensure_input_len(layout, inputs)?;

    let k = layout.counts.num_quotient_chunks;
    if chunk >= k {
        return Err(AceError::InvalidInputLayout {
            message: format!("quotient chunk {chunk} out of range"),
        });
    }

    let z_pow_n = input_value(layout, inputs, InputKey::ZPowN)?;
    let s0 = input_value(layout, inputs, InputKey::S0)?;
    let g = input_value(layout, inputs, InputKey::G)?;
    let weight0 = input_value(layout, inputs, InputKey::Weight0)?;

    let (deltas, weights) = {
        let mut ops = FieldOps;
        compute_deltas_and_weights(k, z_pow_n, s0, g, weight0, &mut ops)
    };

    let mut prod = EF::ONE;
    for (j, delta) in deltas.iter().enumerate() {
        if j != chunk {
            prod *= *delta;
        }
    }

    Ok(weights[chunk] * prod)
}

/// Build DAG nodes that recombine quotient chunks.
pub(crate) fn build_quotient_recomposition_dag<F, EF>(
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
) -> Result<NodeId, AceError>
where
    F: PrimeCharacteristicRing,
    EF: PrimeCharacteristicRing + BasedVectorSpace<F> + Copy + Eq + Hash,
{
    let k = layout.counts.num_quotient_chunks;
    let d = layout.counts.ext_degree;
    let z_pow_n = builder.input(InputKey::ZPowN);
    let s0 = builder.input(InputKey::S0);
    let g = builder.input(InputKey::G);
    let weight0 = builder.input(InputKey::Weight0);

    let (deltas, weights) = {
        let mut ops = DagOps { builder };
        compute_deltas_and_weights(k, z_pow_n, s0, g, weight0, &mut ops)
    };

    let mut chunk_values = Vec::with_capacity(k);
    for chunk in 0..k {
        let mut value = builder.constant(EF::ZERO);
        for coord in 0..d {
            let basis = EF::ith_basis_element(coord).ok_or(AceError::InvalidBasisIndex(coord))?;
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

    Ok(quotient)
}

#[cfg(test)]
fn ensure_input_len<EF>(layout: &InputLayout, inputs: &[EF]) -> Result<(), AceError> {
    if inputs.len() != layout.total_inputs {
        return Err(AceError::InvalidInputLength {
            expected: layout.total_inputs,
            got: inputs.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn input_value<EF>(layout: &InputLayout, inputs: &[EF], key: InputKey) -> Result<EF, AceError>
where
    EF: Copy,
{
    let idx = layout.index(key).ok_or(AceError::InvalidInputKey(key))?;
    inputs.get(idx).copied().ok_or(AceError::InvalidInputLength {
        expected: layout.total_inputs,
        got: inputs.len(),
    })
}

trait Ops<T> {
    fn sub(&mut self, a: T, b: T) -> T;
    fn mul(&mut self, a: T, b: T) -> T;
}

#[cfg(test)]
struct FieldOps;

#[cfg(test)]
impl<EF> Ops<EF> for FieldOps
where
    EF: PrimeCharacteristicRing + Copy,
{
    fn sub(&mut self, a: EF, b: EF) -> EF {
        a - b
    }

    fn mul(&mut self, a: EF, b: EF) -> EF {
        a * b
    }
}

struct DagOps<'a, EF> {
    builder: &'a mut DagBuilder<EF>,
}

impl<'a, EF> Ops<NodeId> for DagOps<'a, EF>
where
    EF: PrimeCharacteristicRing + Copy + Eq + Hash,
{
    fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.builder.sub(a, b)
    }

    fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.builder.mul(a, b)
    }
}

fn compute_deltas_and_weights<T>(
    k: usize,
    z_pow_n: T,
    s0: T,
    g: T,
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
        shift = ops.mul(shift, g);
        weight = ops.mul(weight, g);
    }
    (deltas, weights)
}
