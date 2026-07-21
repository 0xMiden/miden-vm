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

use crate::{AIRS, MIDEN_AIR_COUNT, MidenAir, ProofOrder};

/// Build the combined ACE circuit for the supplied proof order.
///
/// The output circuit evaluates the proof-order Horner fold of the per-AIR alpha-folded
/// constraint roots.
pub fn build_multi_air_ace_circuit_for_order<EF>(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    // Per-AIR main and aux regions are padded to this width before concatenation.
    const LMCS_ALIGNMENT: usize = 8;

    if config.num_airs != MIDEN_AIR_COUNT {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "Miden multi-AIR circuit expects {MIDEN_AIR_COUNT} AIRs, got {}",
                config.num_airs
            ),
        });
    }

    // Build each AIR in the local single-AIR input namespace first. The re-emission pass below
    // maps those local inputs into the combined multi-AIR layout.
    let sub_config = AceConfig { num_airs: 1, ..config };
    let mut sub_dags = Vec::with_capacity(AIRS.len());
    for air in AIRS.iter().copied() {
        let artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(&air, sub_config)?;
        sub_dags.push(build_air_sub_dag::<EF>(air, artifacts, LMCS_ALIGNMENT));
    }

    let global_periodic_max = sub_dags.iter().map(|air| air.periodic_max).max().unwrap_or(0);
    validate_periodic_embedding(&sub_dags, global_periodic_max)?;

    let combined_main_w: usize = sub_dags.iter().map(|air| air.aligned_main).sum();
    let combined_aux_w: usize = sub_dags.iter().map(|air| air.aligned_aux).sum();
    let total_aux_values: usize = sub_dags.iter().map(|air| air.aux_values).sum();

    let reference_counts =
        sub_dags
            .first()
            .map(|air| air.counts)
            .ok_or_else(|| AceError::InvalidInputLayout {
                message: "multi-AIR circuit requires at least one AIR".into(),
            })?;
    for sub_dag in &sub_dags {
        if sub_dag.counts.num_public != reference_counts.num_public
            || sub_dag.counts.num_quotient_chunks != reference_counts.num_quotient_chunks
        {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "{} AIR has incompatible public/quotient counts",
                    sub_dag.air.name()
                ),
            });
        }
    }

    // The final READ layout has one region for each input kind. Per-AIR main, aux, and boundary
    // values are concatenated at the offsets computed for the requested proof order.
    let combined_counts = InputCounts {
        width: combined_main_w,
        aux_width: combined_aux_w,
        num_aux_boundary: total_aux_values,
        num_public: reference_counts.num_public,
        num_randomness: 2,
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
    let mut constraint_acc_by_air = [None; MIDEN_AIR_COUNT];
    // Each per-AIR DAG root has the form `acc - q*v`. The combined circuit folds the
    // per-AIR accumulators in proof order and subtracts one shared quotient binding.
    let mut shared_quotient_binding = None;

    for sub_dag in &sub_dags {
        let offsets = offsets_by_air[sub_dag.air.instance_index()];
        // Re-emit the local DAG without its root; the final root is the proof-order fold below.
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

        let (acc, quotient_binding) =
            translated_acc_and_quotient_binding(sub_dag.air, &sub_dag.dag, &translation)?;
        if let Some(previous_quotient_binding) = shared_quotient_binding {
            if previous_quotient_binding != quotient_binding {
                return Err(AceError::InvalidInputLayout {
                    message: "all AIR quotient bindings must share the same q*v node".into(),
                });
            }
        } else {
            shared_quotient_binding = Some(quotient_binding);
        }
        constraint_acc_by_air[sub_dag.air.instance_index()] = Some(acc);
    }
    let shared_quotient_binding =
        shared_quotient_binding.ok_or_else(|| AceError::InvalidInputLayout {
            message: "multi-AIR circuit did not emit any AIR roots".into(),
        })?;

    let fold_beta = builder.input(InputKey::MultiAirFoldBeta);
    // Fold accumulators in proof order so the circuit matches the proof's AIR ordering.
    let mut ordered = order.airs().iter().copied();
    let first_air = ordered.next().ok_or_else(|| AceError::InvalidInputLayout {
        message: "proof order must contain at least one AIR".into(),
    })?;
    let mut combined_acc = acc_for_air(&constraint_acc_by_air, first_air)?;
    for air in ordered {
        let scaled = builder.mul(combined_acc, fold_beta);
        combined_acc = builder.add(scaled, acc_for_air(&constraint_acc_by_air, air)?);
    }

    let combined_constraint = builder.sub(combined_acc, shared_quotient_binding);

    let mut combined_dag = builder.build(combined_constraint);
    combined_dag.compact();
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

/// Offsets of one AIR's local values inside the combined READ layout.
#[derive(Copy, Clone)]
struct SlotOffsets {
    main: usize,
    aux: usize,
    boundary: usize,
}

/// Local DAG and layout metadata for one AIR before it is re-emitted into the combined circuit.
struct AirSubDag<EF> {
    air: MidenAir,
    dag: AceDag<EF>,
    counts: InputCounts,
    aligned_main: usize,
    aligned_aux: usize,
    aux_values: usize,
    periodic_max: usize,
}

/// Extract the metadata needed to place one AIR in the combined layout.
///
/// `aligned_main` and `aligned_aux` are counted in logical columns, not extension-field
/// coordinates. Aux alignment is applied to coordinates first so that each AIR starts on the same
/// coordinate boundary in the flat READ section.
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

/// Compute where each AIR starts in the combined main, aux, and boundary regions.
///
/// The offsets follow `order`, while the returned array is indexed by `MidenAir::instance_index()`.
/// This lets the re-emission loop process sub-DAGs in canonical order and still write inputs into
/// the proof-order layout.
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

/// Check that each AIR's periodic domain can be evaluated from the shared `ZK` input.
///
/// If an AIR has a shorter periodic cycle than the global maximum, re-emission rewrites `ZK` by
/// repeated squaring. This requires both lengths to be powers of two and the global length to be a
/// multiple of the local length.
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

/// Map a local single-AIR input key into the combined multi-AIR input namespace.
///
/// Main, aux, and boundary inputs are shifted by the AIR's proof-order offsets. Row selectors are
/// replaced by the per-AIR selector slots. Periodic `ZK` is lifted to the global period when the
/// AIR uses a shorter periodic cycle.
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

/// Return the translated accumulator and quotient binding from a re-emitted AIR root.
///
/// Single-AIR ACE roots are expected to have the form `acc - q*v`. The combined circuit keeps the
/// accumulator for proof-order folding and subtracts one shared `q*v` binding at the end.
fn translated_acc_and_quotient_binding<EF>(
    air: MidenAir,
    dag: &AceDag<EF>,
    translation: &[NodeId],
) -> Result<(NodeId, NodeId), AceError> {
    match dag.nodes[dag.root().index()] {
        NodeKind::Sub(acc_id, quotient_binding_id) => {
            Ok((translation[acc_id.index()], translation[quotient_binding_id.index()]))
        },
        _ => Err(AceError::InvalidInputLayout {
            message: format!("{} sub-DAG root must be `Sub(acc, q*v)`", air.name()),
        }),
    }
}

/// Re-emit a DAG into `builder`, rewriting input nodes and preserving the source node order.
///
/// The returned vector maps each source node index to its new node id. When `skip_root` is true,
/// the source root is omitted because the caller builds a different root expression from its
/// children.
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
