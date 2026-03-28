use miden_ace_codegen::{
    AceConfig, EXT_DEGREE, InputKey, InputLayout, LayoutKind, NodeId, NodeKind,
    build_ace_circuit_for_air, build_ace_dag_for_air, emit_circuit,
};
use miden_air::{LiftedAir, ProcessorAir};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing},
    stark::{
        air::symbolic::{
            AirLayout, BaseEntry, BaseLeaf, ConstraintLayout, ExtEntry, ExtLeaf,
            SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt,
        },
        dft::{Radix2DitParallel, TwoAdicSubgroupDft},
    },
};

fn fill_inputs(layout: &InputLayout) -> Vec<QuadFelt> {
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

fn eval_periodic_values(periodic_columns: &[Vec<Felt>], z_k: QuadFelt) -> Vec<QuadFelt> {
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

fn eval_base_expr<F, EF>(
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

fn eval_ext_expr<F, EF>(
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

fn eval_folded_constraints<F, EF>(
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

fn eval_dag(
    nodes: &[NodeKind<QuadFelt>],
    root: NodeId,
    inputs: &[QuadFelt],
    layout: &InputLayout,
) -> QuadFelt {
    let mut values: Vec<QuadFelt> = vec![QuadFelt::ZERO; nodes.len()];
    for (idx, node) in nodes.iter().enumerate() {
        let value = match node {
            NodeKind::Input(key) => inputs[layout.index(*key).unwrap()],
            NodeKind::Constant(c) => *c,
            NodeKind::Add(a, b) => values[a.index()] + values[b.index()],
            NodeKind::Sub(a, b) => values[a.index()] - values[b.index()],
            NodeKind::Mul(a, b) => values[a.index()] * values[b.index()],
            NodeKind::Neg(a) => -values[a.index()],
        };
        values[idx] = value;
    }
    values[root.index()]
}

fn eval_quotient(layout: &InputLayout, inputs: &[QuadFelt]) -> QuadFelt {
    let k = layout.counts.num_quotient_chunks;
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
    let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
    let f = inputs[layout.index(InputKey::F).expect("F in layout")];
    let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

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

    let mut quotient = QuadFelt::ZERO;
    for chunk in 0..k {
        let mut chunk_value = QuadFelt::ZERO;
        for coord in 0..<QuadFelt as BasedVectorSpace<Felt>>::DIMENSION {
            let basis = <QuadFelt as BasedVectorSpace<Felt>>::ith_basis_element(coord)
                .expect("basis index");
            let coord_value = inputs[layout
                .index(InputKey::QuotientChunkCoord { offset: 0, chunk, coord })
                .expect("quotient chunk coord in layout")];
            chunk_value += basis * coord_value;
        }

        let mut prod = QuadFelt::ONE;
        for (idx, delta) in deltas.iter().enumerate() {
            if idx != chunk {
                prod *= *delta;
            }
        }
        quotient += weights[chunk] * prod * chunk_value;
    }

    quotient
}

fn zps_for_chunk(layout: &InputLayout, inputs: &[QuadFelt], chunk: usize) -> QuadFelt {
    let k = layout.counts.num_quotient_chunks;
    assert!(chunk < k, "quotient chunk {chunk} out of range (k={k})");

    let z_pow_n = inputs[layout.index(InputKey::ZPowN).expect("ZPowN in layout")];
    let s0 = inputs[layout.index(InputKey::S0).expect("S0 in layout")];
    let f = inputs[layout.index(InputKey::F).expect("F in layout")];
    let weight0 = inputs[layout.index(InputKey::Weight0).expect("Weight0 in layout")];

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

    let mut prod = QuadFelt::ONE;
    for (idx, delta) in deltas.iter().enumerate() {
        if idx != chunk {
            prod *= *delta;
        }
    }

    weights[chunk] * prod
}

#[test]
fn processor_air_dag_matches_manual_eval() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 2,
        num_vlpi_groups: 0,
        layout: LayoutKind::Native,
    };
    let artifacts = build_ace_dag_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = artifacts.layout.clone();
    let inputs = fill_inputs(&layout);
    let z_k = inputs[layout.index(InputKey::ZK).unwrap()];
    let periodic_values =
        eval_periodic_values(&LiftedAir::<Felt, QuadFelt>::periodic_columns(&air), z_k);

    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: layout.counts.width,
        num_public_values: layout.counts.num_public,
        permutation_width: layout.counts.aux_width,
        num_permutation_challenges: layout.counts.num_randomness,
        num_permutation_values: LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
        num_periodic_columns: layout.counts.num_periodic,
    };
    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(air_layout);
    LiftedAir::<Felt, QuadFelt>::eval(&air, &mut builder);

    let acc = eval_folded_constraints(
        &builder.base_constraints(),
        &builder.extension_constraints(),
        &builder.constraint_layout(),
        &inputs,
        &layout,
        &periodic_values,
    );
    let z_pow_n = inputs[layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let expected = acc - eval_quotient(&layout, &inputs) * vanishing;

    let actual = eval_dag(&artifacts.dag.nodes, artifacts.dag.root, &inputs, &layout);
    assert_eq!(actual, expected);
}

#[test]
#[allow(clippy::print_stdout)]
fn processor_air_chiplet_rows() {
    let air = ProcessorAir;
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
    };

    let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let encoded = circuit.to_ace().unwrap();
    let read_rows = encoded.num_read_rows();
    let eval_rows = encoded.num_eval_rows();
    let total_rows = read_rows + eval_rows;

    println!(
        "ACE chiplet rows (ProcessorAir): read={}, eval={}, total={}, inputs={}, constants={}, nodes={}",
        read_rows,
        eval_rows,
        total_rows,
        encoded.num_inputs(),
        encoded.num_constants(),
        encoded.num_nodes()
    );
}

#[test]
fn synthetic_ood_adjusts_quotient_to_zero() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 0,
        layout: LayoutKind::Masm,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&ProcessorAir, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs = fill_inputs(&artifacts.layout);
    let root = circuit.eval(&inputs).expect("circuit eval");

    let z_pow_n = inputs[artifacts.layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let zps_0 = zps_for_chunk(&artifacts.layout, &inputs, 0);
    let delta = root * (zps_0 * vanishing).inverse();

    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero(), "ACE circuit must evaluate to zero");

    let quotient = eval_quotient(&artifacts.layout, &inputs);
    assert_eq!(quotient, eval_quotient(&artifacts.layout, &inputs));
}

#[test]
fn quotient_next_inputs_do_not_affect_eval() {
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 0,
        layout: LayoutKind::Masm,
    };

    let artifacts =
        build_ace_dag_for_air::<_, Felt, QuadFelt>(&ProcessorAir, config).expect("ace dag");
    let circuit = emit_circuit(&artifacts.dag, artifacts.layout.clone()).expect("ace circuit");

    let mut inputs = fill_inputs(&artifacts.layout);

    let root = circuit.eval(&inputs).expect("circuit eval");
    let z_pow_n = inputs[artifacts.layout.index(InputKey::ZPowN).unwrap()];
    let vanishing = z_pow_n - QuadFelt::ONE;
    let zps_0 = zps_for_chunk(&artifacts.layout, &inputs, 0);
    let delta = root * (zps_0 * vanishing).inverse();
    let idx = artifacts
        .layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    inputs[idx] += delta;
    assert!(
        circuit.eval(&inputs).expect("circuit eval").is_zero(),
        "precondition: zero root"
    );

    for chunk in 0..artifacts.layout.counts.num_quotient_chunks {
        for coord in 0..EXT_DEGREE {
            let idx = artifacts
                .layout
                .index(InputKey::QuotientChunkCoord { offset: 1, chunk, coord })
                .unwrap();
            inputs[idx] += QuadFelt::from(Felt::new(123 + (chunk * 7 + coord) as u64));
        }
    }

    let result = circuit.eval(&inputs).expect("circuit eval");
    assert!(result.is_zero(), "quotient_next should not affect ACE eval");
}
