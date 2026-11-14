//! Test helpers for ACE codegen, available under the `testing` feature or `#[cfg(test)]`.
//!
//! These provide concrete authored AIR execution, periodic-column evaluation, constraint
//! folding, quotient recomposition, and DAG/encoded-stream evaluation for ACE tests and
//! downstream integration tests (e.g. in miden-air).

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use miden_stark::air;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};

use crate::{
    AceError, InputCounts, InputKey, InputLayout,
    compiler::{AceCircuit, AceDag},
    instruction::{Op, decode_instruction},
};

/// Evaluates a multi-AIR relation directly from native sources, independently of DAG lowering.
///
/// Inputs use canonical AIR offsets with each trace region padded to `trace_alignment` base
/// felts. Selectors are per-AIR; periodic columns use the largest period across the AIR set.
/// `proof_order` must be a permutation of the AIR indices. The shared quotient binding is
/// subtracted once, after the beta-Horner fold.
pub fn eval_multi_air_constraints<A>(
    airs: &[A],
    layout: &InputLayout,
    inputs: &[QuadFelt],
    proof_order: &[usize],
    beta: QuadFelt,
    trace_alignment: usize,
) -> QuadFelt
where
    A: air::LiftedAir<F = Felt>,
{
    let specs: Vec<_> = airs.iter().map(air::LiftedAir::spec).collect();
    let shared_period =
        specs.iter().map(air::AirSpec::max_periodic_length).max().unwrap_or(0).max(1);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let (mut public, mut preprocessed, mut main, mut aux, mut boundary) = (0, 0, 0, 0, 0);
    let mut roots = Vec::with_capacity(airs.len());
    for (i, (air, spec)) in airs.iter().zip(&specs).enumerate() {
        let counts = InputCounts {
            preprocessed_width: spec.preprocessed_width(),
            width: spec.main_width,
            aux_width: spec.aux_width,
            num_aux_boundary: spec.num_exports,
            num_public: spec.num_public_values,
            num_randomness: layout.counts.num_randomness,
            num_quotient_chunks: layout.counts.num_quotient_chunks,
        };
        let local = InputLayout::new(counts);
        let mut values = vec![QuadFelt::ZERO; local.total_inputs];
        for (dst, src, offset) in [
            (local.regions.public_values, layout.regions.public_values, public),
            (local.regions.randomness, layout.regions.randomness, 0),
            (local.regions.preprocessed_curr, layout.regions.preprocessed_curr, preprocessed),
            (local.regions.preprocessed_next, layout.regions.preprocessed_next, preprocessed),
            (local.regions.main_curr, layout.regions.main_curr, main),
            (local.regions.main_next, layout.regions.main_next, main),
            (local.regions.aux_curr, layout.regions.aux_curr, aux),
            (local.regions.aux_next, layout.regions.aux_next, aux),
            (local.regions.aux_bus_boundary, layout.regions.aux_bus_boundary, boundary),
        ] {
            values[dst.offset..dst.offset + dst.width]
                .copy_from_slice(&inputs[src.offset + offset..src.offset + offset + dst.width]);
        }
        for (dst, src) in [
            (InputKey::Alpha, InputKey::Alpha),
            (InputKey::IsFirst, InputKey::IsFirstAir(i)),
            (InputKey::IsLast, InputKey::IsLastAir(i)),
            (InputKey::IsTransition, InputKey::IsTransitionAir(i)),
        ] {
            values[local.index(dst).unwrap()] = inputs[layout.index(src).unwrap()];
        }
        let period = spec.max_periodic_length().max(1);
        let periodic_values = eval_periodic_values(
            &spec.periodic_columns,
            z_k.exp_u64((shared_period / period) as u64),
        );
        roots.push(eval_native_constraints(air, spec, &values, &local, &periodic_values));
        public += counts.num_public;
        preprocessed += counts.preprocessed_width.next_multiple_of(trace_alignment);
        main += counts.width.next_multiple_of(trace_alignment);
        aux += (counts.aux_width * crate::EXT_DEGREE).next_multiple_of(trace_alignment);
        boundary += counts.num_aux_boundary;
    }
    let folded = proof_order.iter().fold(QuadFelt::ZERO, |acc, &i| acc * beta + roots[i]);
    let vanishing = inputs[layout.index(InputKey::ZPowN).unwrap()] - QuadFelt::ONE;
    folded - eval_quotient::<Felt, QuadFelt>(layout, inputs) * vanishing
}

/// Direct scalar reference for one snapshotted source; does not use compiler IR or DAG nodes.
///
/// Auxiliary coordinate inputs are QuadFelt values, so reconstruction multiplies each whole
/// coordinate by its extension basis element. The source emits once into the global Horner fold.
pub fn eval_native_constraints<A: air::LiftedAir<F = Felt>>(
    air: &A,
    spec: &air::AirSpec<'_, Felt>,
    inputs: &[QuadFelt],
    layout: &InputLayout,
    periodic_values: &[QuadFelt],
) -> QuadFelt {
    assert_eq!(spec.num_challenges, 2, "ACE source reference requires two challenges");
    let alpha = inputs[layout.index(InputKey::Alpha).unwrap()];
    eval_authored_constraints(air, spec, inputs, layout, periodic_values)
        .into_iter()
        .fold(QuadFelt::ZERO, |accumulator, assertion| {
            let (AuthoredAssertion::Base(value) | AuthoredAssertion::Extension(value)) = assertion;
            accumulator * alpha + value
        })
}

/// One concrete authored emission at an OOD point, retaining its source assertion class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoredAssertion {
    Base(QuadFelt),
    Extension(QuadFelt),
}

#[derive(Default)]
struct AuthoredSink {
    assertions: Vec<AuthoredAssertion>,
}

impl air::LiftedAirBuilder for AuthoredSink {
    type F = Felt;
    type Expr = QuadFelt;
    type ExtExpr = QuadFelt;

    fn emit_base(&mut self, value: QuadFelt, _meta: air::ConstraintMeta<'_>) {
        self.assertions.push(AuthoredAssertion::Base(value));
    }

    fn emit_ext(&mut self, value: QuadFelt, _meta: air::ConstraintMeta<'_>) {
        self.assertions.push(AuthoredAssertion::Extension(value));
    }
}

/// Execute authored equations directly on concrete ACE openings, independently of symbolic IR.
///
/// Both source domains evaluate in `QuadFelt` at the OOD point. Every emission, including its
/// class, global position, repeated roots and zero gates, remains in the returned sequence.
/// Only the source's declared challenge openings are read, up to alpha and beta.
pub fn eval_authored_constraints<A: air::LiftedAir<F = Felt>>(
    air: &A,
    spec: &air::AirSpec<'_, Felt>,
    inputs: &[QuadFelt],
    layout: &InputLayout,
    periodic_values: &[QuadFelt],
) -> Vec<AuthoredAssertion> {
    assert!(spec.num_challenges <= 2, "ACE supplies at most alpha and beta challenges");
    assert_eq!(inputs.len(), layout.total_inputs, "ACE input length");
    assert_eq!(periodic_values.len(), spec.periodic_columns.len(), "periodic input count");
    let main = [0, 1].map(|offset| {
        (0..spec.main_width)
            .map(|index| inputs[layout.index(InputKey::Main { offset, index }).unwrap()])
            .collect::<Vec<_>>()
    });
    let preprocessed = [0, 1].map(|offset| {
        (0..spec.preprocessed_width())
            .map(|index| inputs[layout.index(InputKey::Preprocessed { offset, index }).unwrap()])
            .collect::<Vec<_>>()
    });
    let basis = <QuadFelt as miden_crypto::field::BasedVectorSpace<Felt>>::ith_basis_element(1)
        .expect("quadratic extension basis");
    let auxiliary = [0, 1].map(|offset| {
        (0..spec.aux_width)
            .map(|index| {
                let c0 =
                    inputs[layout.index(InputKey::AuxCoord { offset, index, coord: 0 }).unwrap()];
                let c1 =
                    inputs[layout.index(InputKey::AuxCoord { offset, index, coord: 1 }).unwrap()];
                c0 + basis * c1
            })
            .collect::<Vec<_>>()
    });
    let public_values: Vec<_> = (0..spec.num_public_values)
        .map(|index| inputs[layout.index(InputKey::Public(index)).unwrap()])
        .collect();
    let challenges: Vec<_> = [InputKey::AuxRandAlpha, InputKey::AuxRandBeta]
        .into_iter()
        .take(spec.num_challenges)
        .map(|key| inputs[layout.index(key).expect("declared source challenge in ACE layout")])
        .collect();
    let exports: Vec<_> = (0..spec.num_exports)
        .map(|index| inputs[layout.index(InputKey::AuxBusBoundary(index)).unwrap()])
        .collect();
    let frame = air::AirFrame {
        main: air::Rows { current: &main[0], next: &main[1] },
        preprocessed: air::Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        aux: air::Rows {
            current: &auxiliary[0],
            next: &auxiliary[1],
        },
        periodic: periodic_values,
        selectors: air::Selectors {
            first: inputs[layout.index(InputKey::IsFirst).unwrap()],
            last: inputs[layout.index(InputKey::IsLast).unwrap()],
            transition: inputs[layout.index(InputKey::IsTransition).unwrap()],
        },
    };
    let mut sink = AuthoredSink::default();
    air::LiftedAir::eval(
        air,
        &frame,
        air::UniformInputs {
            public_values: &public_values,
            challenges: &challenges,
            exports: &exports,
        },
        &mut sink,
    );
    sink.assertions
}

/// Deterministic input filler for layout-sized buffers.
///
/// Generates pseudo-random `QuadFelt` values using a simple LCG, suitable for
/// testing against hand-computed reference values.
pub fn fill_inputs(layout: &InputLayout) -> Vec<QuadFelt> {
    let mut values = Vec::with_capacity(layout.total_inputs);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..layout.total_inputs {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let lo = Felt::new_unchecked(state);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let hi = Felt::new_unchecked(state);
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
            crate::compiler::dag::NodeKind::Input(key) => {
                let input_idx = layout.index(*key).ok_or_else(|| AceError::InvalidInputLayout {
                    message: format!("missing input key in layout: {key:?}"),
                })?;
                inputs[input_idx]
            },
            crate::compiler::dag::NodeKind::Constant(c) => *c,
            crate::compiler::dag::NodeKind::Add(a, b) => values[a.index()] + values[b.index()],
            crate::compiler::dag::NodeKind::Sub(a, b) => values[a.index()] - values[b.index()],
            crate::compiler::dag::NodeKind::Mul(a, b) => values[a.index()] * values[b.index()],
            crate::compiler::dag::NodeKind::Neg(a) => -values[a.index()],
        };
        values[idx] = value;
    }

    Ok(values[dag.root().index()])
}

/// Inputs, constant pairs, and operations receive descending node IDs. All arithmetic values
/// come from decoded instructions; the off-VM operation count only locates the root before
/// padding. Padding repeatedly squares that root, preserving its zero set rather than its value.
pub fn eval_encoded_circuit(circuit: &AceCircuit<QuadFelt>, inputs: &[QuadFelt]) -> QuadFelt {
    let encoded = circuit.to_ace().expect("circuit is ACE encodable");
    let stream = encoded.instructions();
    let num_ops = encoded.num_eval_rows();
    let constant_felts = stream.len().checked_sub(num_ops).expect("operation stream length");
    assert!(constant_felts.is_multiple_of(2), "constants have two coordinates");
    let num_constants = constant_felts / 2;
    assert_eq!(encoded.num_vars(), inputs.len() + num_constants, "ACE input count");
    let num_nodes = encoded.num_vars() + num_ops;
    let mut values = vec![None; num_nodes];
    for (index, &input) in inputs.iter().enumerate() {
        values[num_nodes - 1 - index] = Some(input);
    }
    for (index, pair) in stream[..constant_felts].chunks_exact(2).enumerate() {
        values[num_nodes - 1 - inputs.len() - index] = Some(QuadFelt::new([pair[0], pair[1]]));
    }
    for (index, &instruction) in stream[constant_felts..].iter().enumerate() {
        let id = num_ops - 1 - index;
        let (lhs, rhs, op) = decode_instruction(instruction).expect("valid ACE instruction");
        let (lhs, rhs) = (lhs as usize, rhs as usize);
        assert!(lhs > id && lhs < num_nodes, "left operand must precede its operation");
        assert!(rhs > id && rhs < num_nodes, "right operand must precede its operation");
        let lhs = values[lhs].expect("left operand has been evaluated");
        let rhs = values[rhs].expect("right operand has been evaluated");
        values[id] = Some(match op {
            Op::Add => lhs + rhs,
            Op::Sub => lhs - rhs,
            Op::Mul => lhs * rhs,
        });
    }
    let padding = num_ops.checked_sub(circuit.operations.len()).expect("unpadded operation count");
    let root = values[padding].expect("decoded circuit has a root operation");
    assert_eq!(
        values[0].expect("decoded circuit has a final operation"),
        root.exp_power_of_2(padding),
        "encoded padding preserves the root's zero set by repeated squaring",
    );
    root
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
