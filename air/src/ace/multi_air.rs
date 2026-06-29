use alloc::vec::Vec;

use miden_ace_codegen::{
    AceArtifacts, AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputCounts, InputKey,
    InputLayout, NodeId, NodeKind, build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::{Algebra, Field},
    stark::air::{BaseAir, LiftedAir, symbolic::SymbolicExpressionExt},
};

use super::boundary::{batch_logup_boundary_into_builder, multi_air_logup_boundary_config};
use crate::{AIRS, MIDEN_AIR_COUNT, MidenAir, ProofOrder};

/// Build the combined ACE circuit for the supplied proof order.
///
/// The output circuit evaluates `combined + gamma * boundary = 0`, where `combined` is the
/// proof-order Horner fold of the per-AIR alpha-folded roots, and `boundary` is the shared LogUp
/// auxiliary-boundary identity.
pub fn build_multi_air_ace_circuit_for_order<EF>(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    const LMCS_ALIGNMENT: usize = 8;

    let mut sub_dags = Vec::with_capacity(AIRS.len());
    for air in AIRS.iter().copied() {
        let artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(&air, config)?;
        sub_dags.push(build_air_sub_dag::<EF>(air, artifacts, LMCS_ALIGNMENT));
    }

    let global_periodic_max = sub_dags.iter().map(|air| air.periodic_max).max().unwrap_or(0);
    validate_periodic_embedding(&sub_dags, global_periodic_max)?;

    let combined_main_w: usize = sub_dags.iter().map(|air| air.aligned_main).sum();
    let combined_aux_w: usize = sub_dags.iter().map(|air| air.aligned_aux).sum();
    let total_aux_values: usize = sub_dags.iter().map(|air| air.aux_values).sum();
    let total_periodic_columns: usize = sub_dags.iter().map(|air| air.counts.num_periodic).sum();

    let reference_counts =
        sub_dags
            .first()
            .map(|air| air.counts)
            .ok_or_else(|| AceError::InvalidInputLayout {
                message: "multi-AIR circuit requires at least one AIR".into(),
            })?;
    for sub_dag in &sub_dags {
        if sub_dag.counts.num_public != reference_counts.num_public
            || sub_dag.counts.num_vlpi != reference_counts.num_vlpi
            || sub_dag.counts.num_quotient_chunks != reference_counts.num_quotient_chunks
        {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "{} AIR has incompatible public/VLPI/quotient counts",
                    sub_dag.air.name()
                ),
            });
        }
    }

    let combined_counts = InputCounts {
        width: combined_main_w,
        aux_width: combined_aux_w,
        num_aux_boundary: total_aux_values,
        num_public: reference_counts.num_public,
        num_vlpi: reference_counts.num_vlpi,
        num_randomness: 2,
        num_periodic: total_periodic_columns,
        num_quotient_chunks: config.num_quotient_chunks,
    };

    let combined_layout = match config.layout {
        miden_ace_codegen::LayoutKind::Native => {
            InputLayout::new_multi_air(combined_counts, MIDEN_AIR_COUNT)
        },
        miden_ace_codegen::LayoutKind::Masm => {
            InputLayout::new_masm_multi_air(combined_counts, MIDEN_AIR_COUNT)
        },
    };

    let offsets_by_air = air_offsets(&sub_dags, order)?;
    let mut builder = DagBuilder::<EF>::new();
    let mut acc_by_air = [None; MIDEN_AIR_COUNT];
    let mut shared_qv = None;

    for sub_dag in &sub_dags {
        let offsets = offsets_by_air[sub_dag.air.instance_index()];
        let translation = reemit_dag_with_rewrite(
            &mut builder,
            &sub_dag.dag,
            |builder, key| {
                rewrite_air_input(
                    builder,
                    key,
                    sub_dag.air,
                    offsets,
                    sub_dag.periodic_max,
                    global_periodic_max,
                )
            },
            true,
        );

        let (acc, qv) = translated_acc_and_qv(sub_dag.air, &sub_dag.dag, &translation)?;
        if let Some(previous_qv) = shared_qv {
            if previous_qv != qv {
                return Err(AceError::InvalidInputLayout {
                    message: "all AIR quotient bindings must share the same q*v node".into(),
                });
            }
        } else {
            shared_qv = Some(qv);
        }
        acc_by_air[sub_dag.air.instance_index()] = Some(acc);
    }
    let shared_qv = shared_qv.ok_or_else(|| AceError::InvalidInputLayout {
        message: "multi-AIR circuit did not emit any AIR roots".into(),
    })?;

    let beta = builder.input(InputKey::MultiAirBeta);
    let mut ordered = order.airs().iter().copied();
    let first_air = ordered.next().ok_or_else(|| AceError::InvalidInputLayout {
        message: "proof order must contain at least one AIR".into(),
    })?;
    let mut combined_acc = acc_for_air(&acc_by_air, first_air)?;
    for air in ordered {
        let scaled = builder.mul(combined_acc, beta);
        combined_acc = builder.add(scaled, acc_for_air(&acc_by_air, air)?);
    }

    let combined_constraint = builder.sub(combined_acc, shared_qv);
    let boundary_config = multi_air_logup_boundary_config(total_aux_values);
    let final_root =
        batch_logup_boundary_into_builder(&mut builder, combined_constraint, &boundary_config);

    let combined_dag = builder.build(final_root);
    miden_ace_codegen::emit_circuit(&combined_dag, combined_layout)
}

fn acc_for_air(
    acc_by_air: &[Option<NodeId>; MIDEN_AIR_COUNT],
    air: MidenAir,
) -> Result<NodeId, AceError> {
    acc_by_air[air.instance_index()].ok_or_else(|| AceError::InvalidInputLayout {
        message: format!("missing translated acc for {}", air.name()),
    })
}

#[derive(Copy, Clone)]
struct SlotOffsets {
    main: usize,
    aux: usize,
    boundary: usize,
}

struct AirSubDag<EF> {
    air: MidenAir,
    dag: AceDag<EF>,
    counts: InputCounts,
    aligned_main: usize,
    aligned_aux: usize,
    aux_values: usize,
    periodic_max: usize,
}

fn build_air_sub_dag<EF>(
    air: MidenAir,
    artifacts: AceArtifacts<EF>,
    alignment: usize,
) -> AirSubDag<EF>
where
    EF: ExtensionField<Felt>,
{
    let main_width = <MidenAir as BaseAir<Felt>>::width(&air);
    let aux_width = <MidenAir as LiftedAir<Felt, EF>>::aux_width(&air);
    let aux_values = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
    let periodic_columns = <MidenAir as BaseAir<Felt>>::periodic_columns(&air);
    let periodic_max = periodic_columns.iter().map(Vec::len).max().unwrap_or(0);

    let aligned_aux_coord = (aux_width * miden_ace_codegen::EXT_DEGREE).next_multiple_of(alignment);
    assert!(
        aligned_aux_coord.is_multiple_of(miden_ace_codegen::EXT_DEGREE),
        "aligned aux-coordinate width must be even"
    );

    AirSubDag {
        air,
        dag: artifacts.dag,
        counts: artifacts.layout.counts,
        aligned_main: main_width.next_multiple_of(alignment),
        aligned_aux: aligned_aux_coord / miden_ace_codegen::EXT_DEGREE,
        aux_values,
        periodic_max,
    }
}

fn air_offsets<EF>(
    sub_dags: &[AirSubDag<EF>],
    order: &ProofOrder,
) -> Result<[SlotOffsets; MIDEN_AIR_COUNT], AceError> {
    let mut offsets_by_air = [SlotOffsets { main: 0, aux: 0, boundary: 0 }; MIDEN_AIR_COUNT];
    let mut main = 0usize;
    let mut aux = 0usize;
    let mut boundary = 0usize;

    for air in order.airs().iter().copied() {
        let sub_dag =
            sub_dags.get(air.instance_index()).ok_or_else(|| AceError::InvalidInputLayout {
                message: format!("missing sub-DAG for {}", air.name()),
            })?;
        if sub_dag.air != air {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "expected sub-DAG for {}, found {}",
                    air.name(),
                    sub_dag.air.name()
                ),
            });
        }

        offsets_by_air[sub_dag.air.instance_index()] = SlotOffsets { main, aux, boundary };
        main += sub_dag.aligned_main;
        aux += sub_dag.aligned_aux;
        boundary += sub_dag.aux_values;
    }

    Ok(offsets_by_air)
}

fn validate_periodic_embedding<EF>(
    sub_dags: &[AirSubDag<EF>],
    global_periodic_max: usize,
) -> Result<(), AceError> {
    for sub_dag in sub_dags {
        let local = sub_dag.periodic_max;
        if local == 0 {
            continue;
        }
        if global_periodic_max == 0
            || !global_periodic_max.is_multiple_of(local)
            || !global_periodic_max.is_power_of_two()
            || !local.is_power_of_two()
        {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "{} periodic max ({local}) does not embed in global max ({global_periodic_max})",
                    sub_dag.air.name()
                ),
            });
        }
    }
    Ok(())
}

fn rewrite_air_input<EF>(
    builder: &mut DagBuilder<EF>,
    key: InputKey,
    air: MidenAir,
    offsets: SlotOffsets,
    local_periodic_max: usize,
    global_periodic_max: usize,
) -> NodeId
where
    EF: Field,
{
    match key {
        InputKey::Main { offset, index } => {
            builder.input(InputKey::Main { offset, index: index + offsets.main })
        },
        InputKey::AuxCoord { offset, index, coord } => builder.input(InputKey::AuxCoord {
            offset,
            index: index + offsets.aux,
            coord,
        }),
        InputKey::AuxBusBoundary(slot) => {
            builder.input(InputKey::AuxBusBoundary(slot + offsets.boundary))
        },
        InputKey::IsFirst => builder.input(InputKey::IsFirstAir(air.instance_index())),
        InputKey::IsLast => builder.input(InputKey::IsLastAir(air.instance_index())),
        InputKey::IsTransition => builder.input(InputKey::IsTransitionAir(air.instance_index())),
        InputKey::ZK if local_periodic_max != 0 && local_periodic_max != global_periodic_max => {
            let mut z = builder.input(InputKey::ZK);
            let ratio = global_periodic_max / local_periodic_max;
            for _ in 0..ratio.ilog2() {
                z = builder.mul(z, z);
            }
            z
        },
        other => builder.input(other),
    }
}

fn translated_acc_and_qv<EF>(
    air: MidenAir,
    dag: &AceDag<EF>,
    translation: &[NodeId],
) -> Result<(NodeId, NodeId), AceError> {
    match dag.nodes[dag.root().index()] {
        NodeKind::Sub(acc_id, qv_id) => {
            Ok((translation[acc_id.index()], translation[qv_id.index()]))
        },
        _ => Err(AceError::InvalidInputLayout {
            message: format!("{} sub-DAG root must be `Sub(acc, q*v)`", air.name()),
        }),
    }
}

fn reemit_dag_with_rewrite<EF, F>(
    builder: &mut DagBuilder<EF>,
    source: &AceDag<EF>,
    rewrite: F,
    skip_root: bool,
) -> Vec<NodeId>
where
    EF: Field,
    F: Fn(&mut DagBuilder<EF>, InputKey) -> NodeId,
{
    let nodes = &source.nodes;
    let limit = if skip_root && !nodes.is_empty() {
        nodes.len() - 1
    } else {
        nodes.len()
    };
    let mut translation = Vec::with_capacity(nodes.len());
    for node in nodes.iter().take(limit) {
        let new_id = match *node {
            NodeKind::Input(key) => rewrite(builder, key),
            NodeKind::Constant(v) => builder.constant(v),
            NodeKind::Add(a, b) => builder.add(translation[a.index()], translation[b.index()]),
            NodeKind::Sub(a, b) => builder.sub(translation[a.index()], translation[b.index()]),
            NodeKind::Mul(a, b) => builder.mul(translation[a.index()], translation[b.index()]),
            NodeKind::Neg(a) => builder.neg(translation[a.index()]),
        };
        translation.push(new_id);
    }
    translation
}
