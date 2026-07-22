//! ACE circuit integration for the precompile chiplet multi-AIR proof.
//!
//! The circuit checks the β-folded constraint composition of every chiplet AIR in
//! [`ChipletAir::all`]. The cross-chiplet LogUp identity enforced by
//! `ChipletMultiAir::eval_external` is not folded into this circuit; it remains an external
//! multi-AIR assertion.

use alloc::vec::Vec;

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, NodeKind,
    build_ace_dags_for_airs,
};
use miden_core::{
    Felt,
    field::{ExtensionField, QuadFelt},
};
use miden_crypto::stark::air::{BaseAir, LiftedAir};

use crate::session::ChipletAir;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Build the combined ACE circuit for the precompile chiplet multi-AIR proof.
///
/// The output circuit evaluates `combined = 0`, where `combined` is the beta-Horner fold of the
/// per-AIR alpha-folded constraint roots minus the shared `q·v` quotient binding. The
/// cross-chiplet LogUp boundary identity is checked separately by `ChipletMultiAir::eval_external`.
///
/// Implementation strategy mirrors `miden_air::ace::build_multi_air_ace_circuit`:
/// 1. Build the chiplet AIR sub-DAGs with single-AIR layouts via [`build_ace_dags_for_airs`]. These
///    DAGs encode each AIR's constraints using layout-relative
///    `InputKey::Preprocessed`/`Main`/`AuxCoord`/`AuxBusBoundary` slots.
/// 2. Re-emit each sub-DAG's nodes into a fresh [`DagBuilder`] configured for the combined layout,
///    shifting preprocessed/main/aux/bus-boundary slot indices into that AIR's subregion and
///    tagging row selectors with the AIR's `ChipletAir::all()` instance index.
/// 3. Fold all AIR accumulators with `MultiAirFoldBeta` and subtract the single shared `q·v`
///    quotient binding.
///
/// The fold uses the canonical [`ChipletAir::all()`] instance order. This circuit is committed as
/// the precompile relation identifier; the lifted STARK prover independently derives proof order
/// from trace heights.
pub fn build_precompile_multi_air_ace_circuit(
    config: AceConfig,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    use miden_ace_codegen::{InputCounts, InputLayout};

    let airs = ChipletAir::all();
    assert_eq!(
        config.num_airs,
        airs.len(),
        "build_precompile_multi_air_ace_circuit builds the {}-AIR precompile circuit; \
         AceConfig::num_airs must match",
        airs.len(),
    );

    // LMCS commits each per-AIR matrix as a stack and aligns each matrix's column count to the
    // LMCS rate (8 for Poseidon2). The wire OOD opens carry data in aligned per-AIR widths
    // concatenated across AIRs, so the combined layout uses those aligned widths. Padding slots
    // within each AIR's subregion are unreferenced by the constraints.
    const LMCS_ALIGNMENT: usize = 8;

    struct AirParts<EF> {
        dag: AceDag<EF>,
        aligned_preprocessed: usize,
        aligned_main: usize,
        aligned_aux_coord: usize,
        aux_n: usize,
    }

    let sub_config = AceConfig { num_airs: 1, ..config };
    let artifacts = build_ace_dags_for_airs::<ChipletAir, Felt, QuadFelt>(&airs, sub_config)?;
    let mut parts: Vec<AirParts<QuadFelt>> = Vec::with_capacity(airs.len());
    for (air, artifacts) in airs.iter().zip(artifacts) {
        let preprocessed_w = <ChipletAir as BaseAir<Felt>>::preprocessed_width(air);
        let main_w = <ChipletAir as BaseAir<Felt>>::width(air);
        let aux_w = <ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(air);
        parts.push(AirParts {
            dag: artifacts.dag,
            aligned_preprocessed: preprocessed_w.next_multiple_of(LMCS_ALIGNMENT),
            aligned_main: main_w.next_multiple_of(LMCS_ALIGNMENT),
            aligned_aux_coord: (aux_w * miden_ace_codegen::EXT_DEGREE)
                .next_multiple_of(LMCS_ALIGNMENT),
            aux_n: <ChipletAir as LiftedAir<Felt, QuadFelt>>::num_aux_values(air),
        });
    }

    let num_public = <ChipletAir as BaseAir<Felt>>::num_public_values(&airs[0]);
    for air in &airs[1..] {
        assert_eq!(
            <ChipletAir as BaseAir<Felt>>::num_public_values(air),
            num_public,
            "all precompile chiplet AIRs must share the public-value window",
        );
    }

    let combined_aux_coord_w: usize = parts.iter().map(|p| p.aligned_aux_coord).sum();
    assert!(
        combined_aux_coord_w.is_multiple_of(miden_ace_codegen::EXT_DEGREE),
        "combined aux coord width must be divisible by extension degree",
    );
    let combined_counts = InputCounts {
        preprocessed_width: parts.iter().map(|p| p.aligned_preprocessed).sum(),
        width: parts.iter().map(|p| p.aligned_main).sum(),
        aux_width: combined_aux_coord_w / miden_ace_codegen::EXT_DEGREE,
        num_aux_boundary: parts.iter().map(|p| p.aux_n).sum(),
        num_public,
        num_randomness: 2,
        num_quotient_chunks: config.num_quotient_chunks,
    };

    // Every constraint references a public value within the AIRs' shared public window; fail loudly
    // if one ever addresses a slot outside it.
    let check_public = |index: usize| -> InputKey {
        assert!(
            index < num_public,
            "constraint references public value {index} outside the {num_public}-felt window",
        );
        InputKey::Public(index)
    };

    let combined_layout = match config.layout {
        miden_ace_codegen::LayoutKind::Native => {
            InputLayout::new_multi_air(combined_counts, config.num_airs)
        },
        miden_ace_codegen::LayoutKind::Masm => {
            InputLayout::new_masm_multi_air(combined_counts, config.num_airs)
        },
    };

    let mut builder = DagBuilder::<QuadFelt>::new();
    let mut preprocessed_offset = 0usize;
    let mut main_offset = 0usize;
    let mut aux_w_offset = 0usize;
    let mut boundary_offset = 0usize;
    let mut accs: Vec<NodeId> = Vec::with_capacity(parts.len());
    let mut shared_qv: Option<NodeId> = None;

    for (air_index, part) in parts.iter().enumerate() {
        let root_old = part.dag.root();
        let translation = reemit_dag_with_rewrite(
            &mut builder,
            &part.dag,
            |key| match key {
                InputKey::Preprocessed { offset, index } => InputKey::Preprocessed {
                    offset,
                    index: index + preprocessed_offset,
                },
                InputKey::Main { offset, index } => {
                    InputKey::Main { offset, index: index + main_offset }
                },
                InputKey::AuxCoord { offset, index, coord } => InputKey::AuxCoord {
                    offset,
                    index: index + aux_w_offset,
                    coord,
                },
                InputKey::AuxBusBoundary(slot) => InputKey::AuxBusBoundary(slot + boundary_offset),
                InputKey::IsFirst => InputKey::IsFirstAir(air_index),
                InputKey::IsLast => InputKey::IsLastAir(air_index),
                InputKey::IsTransition => InputKey::IsTransitionAir(air_index),
                InputKey::Public(i) => check_public(i),
                other => other,
            },
            true,
        );

        // Each sub-DAG root is `Sub(acc, q*v)`: extract the alpha-folded `acc` and the quotient
        // binding `q*v`, which must be the same hash-consed node across every AIR.
        let (acc, qv) = match part.dag.nodes[root_old.index()] {
            NodeKind::Sub(acc_id, qv_id) => {
                (translation[acc_id.index()], translation[qv_id.index()])
            },
            _ => panic!("per-AIR sub-DAG root must be `Sub(acc, q*v)`"),
        };
        match shared_qv {
            None => shared_qv = Some(qv),
            Some(expected) if expected != qv => {
                return Err(AceError::InvalidInputLayout {
                    message: "per-AIR quotient bindings must share the same q*v node".into(),
                });
            },
            Some(_) => {},
        }
        accs.push(acc);

        preprocessed_offset += part.aligned_preprocessed;
        main_offset += part.aligned_main;
        aux_w_offset += part.aligned_aux_coord / miden_ace_codegen::EXT_DEGREE;
        boundary_offset += part.aux_n;
    }

    let shared_qv = shared_qv.expect("multi-AIR circuit requires at least one AIR");

    let fold_beta = builder.input(InputKey::MultiAirFoldBeta);
    let mut accs = accs.into_iter();
    let mut combined_acc = accs.next().expect("multi-AIR circuit requires at least one AIR");
    for acc in accs {
        let scaled = builder.mul(combined_acc, fold_beta);
        combined_acc = builder.add(scaled, acc);
    }
    // SAFETY-CRITICAL invariant: this `sub` must be the last operation emitted into the builder,
    // since the MASM ACE chip's "is the last op zero?" check evaluates that node as the root.
    let combined_constraint = builder.sub(combined_acc, shared_qv);

    let combined_dag = builder.build(combined_constraint);
    miden_ace_codegen::emit_circuit(&combined_dag, combined_layout)
}

/// Re-emit `source` into `builder`, rewriting each `Input(key)` via `rewrite`.
///
/// Returns a translation table mapping source DAG node indices to corresponding nodes in `builder`.
/// `skip_root` skips the source DAG's root node, allowing callers to extract and rewire the
/// children of the per-AIR `Sub(acc, q*v)` root.
fn reemit_dag_with_rewrite<EF, F>(
    builder: &mut DagBuilder<EF>,
    source: &AceDag<EF>,
    rewrite: F,
    skip_root: bool,
) -> Vec<NodeId>
where
    EF: ExtensionField<Felt>,
    F: Fn(InputKey) -> InputKey,
{
    let nodes = &source.nodes;
    let limit = if skip_root && !nodes.is_empty() {
        nodes.len() - 1
    } else {
        nodes.len()
    };
    let mut translation: Vec<NodeId> = Vec::with_capacity(nodes.len());
    for node in nodes.iter().take(limit) {
        let new_id = match *node {
            NodeKind::Input(key) => builder.input(rewrite(key)),
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

#[cfg(test)]
mod tests {
    use miden_ace_codegen::{AceConfig, LayoutKind};

    use super::build_precompile_multi_air_ace_circuit;
    use crate::session::NUM_CHIPLETS;

    #[test]
    fn precompile_multi_air_ace_circuit_builds() {
        let config = AceConfig {
            num_quotient_chunks: 8,
            layout: LayoutKind::Masm,
            num_airs: NUM_CHIPLETS,
        };

        let circuit = build_precompile_multi_air_ace_circuit(config)
            .expect("precompile multi-AIR ACE circuit");
        assert_eq!(circuit.layout().counts.num_public, crate::logup::NUM_PUBLIC_VALUES);
        assert_eq!(circuit.layout().counts.num_aux_boundary, NUM_CHIPLETS);
        assert!(circuit.layout().counts.preprocessed_width >= 8);
    }
}
