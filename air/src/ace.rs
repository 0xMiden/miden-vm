//! ACE circuit integration for the multi-AIR proof.
//!
//! The circuit checks the β-folded constraint composition of the AIRs. The
//! LogUp auxiliary-trace boundary identity
//!
//! ```text
//! 0  =  Σ_i n_i · sigma_prime_i
//!         + c_block_hash
//!         + c_log_precompile
//!         + c_kernel_rom
//! ```
//!
//! is checked outside the circuit, where `sigma_prime_i` is the normalized committed LogUp sum
//! for AIR `i` and `n_i` is its trace length.

use alloc::vec::Vec;

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, NodeKind,
    build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::Algebra,
    stark::air::{BaseAir, LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::MidenAir;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Build the combined ACE circuit for the VM's multi-AIR proof.
///
/// The output circuit evaluates
///   `combined = 0`
/// where `combined = Σ_i MultiAirBeta(i) · acc_i - q·v` is the β-folded sum of the per-AIR
/// alpha-folded constraint roots minus the shared quotient binding. The cross-AIR LogUp
/// boundary identity over trace-length-weighted normalized LogUp sums is checked separately,
/// outside the circuit.
///
/// Implementation strategy:
/// 1. Build each AIR's sub-DAG with its own (single-AIR) layout via [`build_ace_dag_for_air`].
///    These DAGs encode each AIR's alpha-folded constraints referencing layout-relative
///    `InputKey::Main`/`AuxCoord`/`AuxBusBoundary` slots.
/// 2. Re-emit each sub-DAG's nodes into a fresh `DagBuilder` configured for the *combined* layout,
///    shifting its main/aux/bus-boundary slot indices into that AIR's subregion (the first AIR
///    passes through unchanged) and tagging its selectors with the AIR's instance index.
/// 3. β-fold: `combined = Σ_i MultiAirBeta(i) · acc_i - q·v`, where the verifier sets one
///    coefficient to β and the others to 1 based on proof_order.
///
/// Returns the combined `AceCircuit` ready for emission to the MASM ACE chip.
pub fn build_multi_air_ace_circuit<EF>(config: AceConfig) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    use miden_ace_codegen::{InputCounts, InputLayout};

    // The AIRs combined by the VM proof, in canonical (commit-order-independent) order.
    let airs = [MidenAir::CORE, MidenAir::CHIPLETS];
    assert_eq!(
        config.num_airs,
        airs.len(),
        "build_multi_air_ace_circuit builds the {}-AIR VM circuit; AceConfig::num_airs must match",
        airs.len(),
    );

    // LMCS commits each per-AIR matrix as a stack and aligns each matrix's column count to the
    // LMCS rate (8 for Poseidon2). The wire OOD opens carry data in *aligned* per-AIR widths
    // concatenated across AIRs, so the combined layout uses those aligned widths (trailing slots
    // are unreferenced padding) to line up with the wire format byte-for-byte. This mirrors what
    // `verify_aligned` does internally before truncation.
    const LMCS_ALIGNMENT: usize = 8;

    // Per-AIR sub-DAG plus the LMCS-aligned widths and boundary/periodic counts the combined
    // layout needs.
    struct AirParts<EF> {
        dag: AceDag<EF>,
        aligned_main: usize,
        aligned_aux_coord: usize,
        aux_n: usize,
        num_periodic: usize,
    }

    // Each sub-DAG is built with its own single-AIR layout so the symbolic
    // eval references plain `InputKey` variants.
    let sub_config = AceConfig { num_airs: 1, ..config };
    let mut parts: Vec<AirParts<EF>> = Vec::with_capacity(airs.len());
    for air in &airs {
        let artifacts = build_ace_dag_for_air::<MidenAir, Felt, EF>(air, sub_config)?;
        let main_w = <MidenAir as BaseAir<Felt>>::width(air);
        let aux_w = <MidenAir as LiftedAir<Felt, EF>>::aux_width(air);
        parts.push(AirParts {
            dag: artifacts.dag,
            aligned_main: main_w.next_multiple_of(LMCS_ALIGNMENT),
            aligned_aux_coord: (aux_w * miden_ace_codegen::EXT_DEGREE)
                .next_multiple_of(LMCS_ALIGNMENT),
            aux_n: <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(air),
            num_periodic: artifacts.layout.counts.num_periodic,
        });
    }

    // Combined input counts.
    //
    // - `width` and `aux_width` sum the LMCS-aligned per-AIR widths so the codegen layout matches
    //   the wire byte order exactly. Padding slots within each AIR's subregion are unreferenced by
    //   the constraints (each AIR's eval body only addresses columns up to its original width).
    // - `num_public` is the AIRs' shared public-value count (the stack-i/o felts). The program hash
    //   and transcript state are statement `aux_inputs`, not read by any AIR constraint, so they
    //   never enter the ACE READ section.
    // - `num_aux_boundary` sums each AIR's boundary slot count.
    // - `num_periodic` comes from the single AIR that declares periodic columns (the others
    //   contribute none); the combined `LiftedAir` wrapper exposes them once.
    let num_public = <MidenAir as BaseAir<Felt>>::num_public_values(&airs[0]);
    let combined_aux_coord_w: usize = parts.iter().map(|p| p.aligned_aux_coord).sum();
    assert!(
        combined_aux_coord_w.is_multiple_of(miden_ace_codegen::EXT_DEGREE),
        "combined aux coord width must be even"
    );
    let combined_counts = InputCounts {
        width: parts.iter().map(|p| p.aligned_main).sum(),
        aux_width: combined_aux_coord_w / miden_ace_codegen::EXT_DEGREE,
        num_aux_boundary: parts.iter().map(|p| p.aux_n).sum(),
        num_public,
        num_randomness: 2,
        num_periodic: parts.iter().map(|p| p.num_periodic).max().unwrap_or(0),
        num_quotient_chunks: config.num_quotient_chunks,
    };

    // Every constraint references a public value within the AIRs' shared public window; fail
    // loudly if one ever addresses a slot outside it.
    let check_public = |index: usize| -> InputKey {
        assert!(
            index < num_public,
            "constraint references public value {index} outside the {num_public}-felt window",
        );
        InputKey::Public(index)
    };

    // Build combined layout via the multi-air constructors so the stark-vars region
    // includes the multi-AIR β coefficients and per-AIR selector slots.
    let combined_layout = match config.layout {
        miden_ace_codegen::LayoutKind::Native => {
            InputLayout::new_multi_air(combined_counts, config.num_airs)
        },
        miden_ace_codegen::LayoutKind::Masm => {
            InputLayout::new_masm_multi_air(combined_counts, config.num_airs)
        },
    };

    // Re-emit each per-AIR sub-DAG into the combined builder, shifting its main / aux /
    // bus-boundary slot indices into that AIR's subregion of the combined layout and tagging its
    // selectors with the AIR's instance index. The cumulative offsets are zero for the first AIR
    // (which passes through unchanged) and grow by each AIR's aligned widths. `InputKey` indices
    // are in column / EF units, so the aux shift uses the EF-count of the preceding aligned aux
    // regions.
    let mut builder = DagBuilder::<EF>::new();
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
            true, // skip each sub-DAG's `Sub(acc, q*v)` root — the combined formula shares one q*v
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

        main_offset += part.aligned_main;
        aux_w_offset += part.aligned_aux_coord / miden_ace_codegen::EXT_DEGREE;
        boundary_offset += part.aux_n;
    }

    let shared_qv = shared_qv.expect("multi-AIR circuit requires at least one AIR");

    // β-fold: `combined = Σ_i MultiAirBeta(i) · acc_i - q*v`. The verifier assigns β to the AIR at
    // proof_order position 0 and 1 to the others. Emit all β inputs, then all per-AIR terms, then
    // the running sum, matching the layout/MASM ordering.
    let mabs: Vec<NodeId> =
        (0..accs.len()).map(|i| builder.input(InputKey::MultiAirBeta(i))).collect();
    let mut combined_acc: Option<NodeId> = None;
    for (mab, acc) in mabs.iter().zip(&accs) {
        let term = builder.mul(*mab, *acc);
        combined_acc = Some(match combined_acc {
            None => term,
            Some(prev) => builder.add(prev, term),
        });
    }
    let combined_acc = combined_acc.expect("multi-AIR circuit requires at least one AIR");
    // SAFETY-CRITICAL invariant: this `sub` must be the *last* operation emitted into the
    // builder, since the MASM ACE chip's "is the last op zero?" check evaluates that node
    // as the root.
    let combined_constraint = builder.sub(combined_acc, shared_qv);

    let combined_dag = builder.build(combined_constraint);
    miden_ace_codegen::emit_circuit(&combined_dag, combined_layout)
}

/// Re-emit `source` into `builder`, rewriting each `Input(key)` via `rewrite`.
///
/// Returns a translation table mapping the source DAG's node indices to the
/// corresponding `NodeId`s in `builder`. The source DAG's nodes must be in
/// topological order (which they are by `DagBuilder::intern` construction).
///
/// `skip_root` skips the source DAG's root node (the last node) when re-emitting.
/// Useful when the caller intends to bypass the source's top-level expression and
/// wire up children directly (e.g., extracting `acc` from a `Sub(acc, q*v)` root
/// when the `q*v` subtraction is replaced by a shared one in the combined DAG).
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
