//! Quotient recomposition helpers shared by the DAG builder and tests.
//!
//! These routines mirror the verifier's barycentric recomposition of quotient
//! chunks. They are intentionally centralized to keep DAG lowering and tests
//! aligned.

use miden_crypto::field::{ExtensionField, Field};

#[cfg(test)]
use crate::AceError;
use crate::{
    dag::{DagBuilder, NodeId},
    layout::{InputKey, InputLayout},
};

/// Evaluate the quotient recomposition at `zeta` using provided inputs.
#[cfg(test)]
pub fn eval_quotient<F, EF>(layout: &InputLayout, inputs: &[EF]) -> Result<EF, AceError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    if inputs.len() != layout.total_inputs {
        return Err(AceError::InvalidInputLength {
            expected: layout.total_inputs,
            got: inputs.len(),
        });
    }

    let k = layout.counts.num_quotient_chunks;
    if layout.counts.quotient_extension {
        // Power-sum recomposition:
        // Q(z) = sum_j chunk[j] * z^{j * segment_len}
        let z_k = inputs[layout.index(InputKey::ZK).expect("ZK in layout")];
        let z_step = z_k.exp_u64(layout.counts.quotient_segment_len as u64);

        let mut quotient = EF::ZERO;
        let mut pow = EF::ONE;
        for chunk in 0..k {
            let chunk_value = inputs[layout
                .index(InputKey::QuotientChunk { offset: 0, chunk })
                .expect("quotient chunk in layout")];
            quotient += chunk_value * pow;
            pow *= z_step;
        }
        Ok(quotient)
    } else {
        // Barycentric Lagrange recomposition (Miden VM convention).
        let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
        let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
        let f = inputs[layout.index(InputKey::F).expect("F in layout")];
        let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

        let (deltas, weights) = {
            let mut ops = FieldOps;
            compute_deltas_and_weights(k, z_pow_n, s0, f, weight0, &mut ops)
        };

        let mut chunk_values = Vec::with_capacity(k);
        for chunk in 0..k {
            let mut v = EF::ZERO;
            for coord in 0..EF::DIMENSION {
                let basis =
                    EF::ith_basis_element(coord).expect("basis index within extension degree");
                let coord_value = inputs[layout
                    .index(InputKey::QuotientChunkCoord { offset: 0, chunk, coord })
                    .expect("quotient chunk coord in layout")];
                v += basis * coord_value;
            }
            chunk_values.push(v);
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
}

/// Compute the barycentric kernel value (`zps`) for a single chunk.
#[cfg(test)]
pub fn zps_for_chunk<EF>(layout: &InputLayout, inputs: &[EF], chunk: usize) -> Result<EF, AceError>
where
    EF: Field,
{
    if inputs.len() != layout.total_inputs {
        return Err(AceError::InvalidInputLength {
            expected: layout.total_inputs,
            got: inputs.len(),
        });
    }

    let k = layout.counts.num_quotient_chunks;
    assert!(chunk < k, "quotient chunk {chunk} out of range (k={k})");

    if layout.counts.quotient_extension {
        let z_k = inputs[layout.index(InputKey::ZK).expect("ZK in layout")];
        let z_step = z_k.exp_u64(layout.counts.quotient_segment_len as u64);
        Ok(z_step.exp_u64(chunk as u64))
    } else {
        let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
        let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
        let f = inputs[layout.index(InputKey::F).expect("F in layout")];
        let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

        let (deltas, weights) = {
            let mut ops = FieldOps;
            compute_deltas_and_weights(k, z_pow_n, s0, f, weight0, &mut ops)
        };

        let mut prod = EF::ONE;
        for (j, delta) in deltas.iter().enumerate() {
            if j != chunk {
                prod *= *delta;
            }
        }

        Ok(weights[chunk] * prod)
    }
}

/// Build DAG nodes that recombine quotient chunks.
///
/// Two modes:
/// - `quotient_extension = false` (Miden VM): barycentric Lagrange recomposition from coset-split
///   quotient chunks. Uses `s0`, `f`, `weight0`, `z^N`.
/// - `quotient_extension = true` (miden-signature): power-sum recomposition from
///   coefficient-segment chunks: `Q(z) = sum_j chunk_j * z^{j * segment_len}`. Uses `z_k` (= z) and
///   `segment_len` from the layout counts.
pub(crate) fn build_quotient_recomposition_dag<F, EF>(
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
) -> NodeId
where
    F: Field,
    EF: ExtensionField<F>,
{
    let k = layout.counts.num_quotient_chunks;

    if layout.counts.quotient_extension {
        // Power-sum recomposition: Q(z) = sum_j chunk_j(z) * z^{j * segment_len}
        //
        // z_step = z^segment_len, computed from z_k (which equals z for our AIR).
        // Horner form: Q = chunk[0] + z_step * (chunk[1] + z_step * (... + z_step * chunk[k-1]))
        let z_k = builder.input(InputKey::ZK);
        let seg_len = layout.counts.quotient_segment_len;

        // Compute z_step = z_k^segment_len via repeated squaring in the DAG.
        let z_step = dag_pow(builder, z_k, seg_len);

        // Read chunk values
        let chunk_values: Vec<NodeId> = (0..k)
            .map(|chunk| builder.input(InputKey::QuotientChunk { offset: 0, chunk }))
            .collect();

        // Horner: acc = chunk[k-1]; for j = k-2..0: acc = acc * z_step + chunk[j]
        let mut acc = chunk_values[k - 1];
        for j in (0..k - 1).rev() {
            acc = builder.mul(acc, z_step);
            acc = builder.add(acc, chunk_values[j]);
        }
        acc
    } else {
        // Barycentric Lagrange recomposition (Miden VM convention).
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
            let mut v = builder.constant(EF::ZERO);
            for coord in 0..EF::DIMENSION {
                let basis =
                    EF::ith_basis_element(coord).expect("basis index within extension degree");
                let coord_node =
                    builder.input(InputKey::QuotientChunkCoord { offset: 0, chunk, coord });
                let basis_node = builder.constant(basis);
                let term = builder.mul(basis_node, coord_node);
                v = builder.add(v, term);
            }
            chunk_values.push(v);
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
}

/// Compute x^n in the DAG via repeated squaring.
fn dag_pow<EF: Field>(builder: &mut DagBuilder<EF>, base: NodeId, exp: usize) -> NodeId {
    if exp == 0 {
        return builder.constant(EF::ONE);
    }
    let mut result = base;
    let n = exp;
    // Find highest bit
    let bits = usize::BITS - n.leading_zeros();
    // Square-and-multiply from second-highest bit down
    for i in (0..bits - 1).rev() {
        result = builder.mul(result, result);
        if (n >> i) & 1 == 1 {
            result = builder.mul(result, base);
        }
    }
    result
}

#[cfg(test)]
struct FieldOps;

#[cfg(test)]
impl<EF> Ops<EF> for FieldOps
where
    EF: Field,
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
