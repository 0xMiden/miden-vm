//! Geometry and MASM rendering of the PVM out-of-domain row hook.
//!
//! The proof commits each chiplet's trace at its position in the height-sorted proof order, while
//! the canonical ACE circuit reads that trace at the chiplet's instance-order offset. The gap is
//! closed at ingest: the transcript absorb and the DEEP Horner accumulation stay positional over
//! the advice stream, and only `adv_pipe`'s destination is retargeted at segment boundaries.
//!
//! Everything below is derived from the compiled relation's chiplet widths, so a chiplet width
//! change moves the destinations, the `pipe_k` set and the dispatch table together.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write as _;
#[cfg(test)]
use core::ops::Range;

use miden_ace_codegen::{
    EXT_DEGREE, InputKey, InputLayout, OodScatterPlan, ProofOrderMapsConfig, RelationGeometry,
    render_proof_order_maps,
};
use miden_air::precompiles::{ChipletAir, NUM_CHIPLETS};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{BaseAir, LiftedAir};

/// Per-AIR trace regions are padded to this width before concatenation into a commitment group.
const LMCS_ALIGNMENT: usize = 8;

/// Felts moved by one `adv_pipe`.
///
/// This transport width governs block/segment arithmetic and destination alignment;
/// [`LMCS_ALIGNMENT`] independently governs column-padding widths.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Felts reserved for the out-of-domain scatter table by `sys/pvm/layout.masm`.
pub(crate) const OOD_SCATTER_TABLE_FELTS: u32 = 96;

// ROW GEOMETRY
// ================================================================================================

/// Aligned per-chiplet widths of one out-of-domain row, in canonical instance order.
///
/// Widths count evaluation slots: one per committed base column, or per auxiliary coordinate.
/// Each slot is one quadratic-extension value, hence [`EXT_DEGREE`] felts on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PvmOodGeometry {
    pub(crate) preprocessed: Vec<usize>,
    pub(crate) main: Vec<usize>,
    pub(crate) aux: Vec<usize>,
    /// Shared across chiplets: the quotient is one recomposed matrix, not a per-AIR one.
    pub(crate) quotient: usize,
}

impl PvmOodGeometry {
    /// Derives the row geometry from the compiled relation's chiplet widths and cross-checks it
    /// against the circuit's own input layout.
    pub(crate) fn from_compiled(
        compiled: &RelationGeometry,
        layout: &InputLayout,
    ) -> Result<Self, String> {
        if compiled.trace_alignment != LMCS_ALIGNMENT {
            return Err(format!(
                "the PVM relation is compiled with trace alignment {}, expected {LMCS_ALIGNMENT}",
                compiled.trace_alignment
            ));
        }
        let preprocessed = compiled.airs.iter().map(|air| air.preprocessed.width).collect();
        let main = compiled.airs.iter().map(|air| air.main.width).collect();
        let aux = compiled.airs.iter().map(|air| air.aux.width).collect();
        let aux_values: Vec<_> = compiled.airs.iter().map(|air| air.num_aux_boundary).collect();
        if aux_values.iter().any(|&count| count != 1) {
            return Err(format!(
                "the PVM proof-order boundary scatter requires exactly one auxiliary value per \
                 chiplet, got {aux_values:?}"
            ));
        }
        let geometry = Self {
            preprocessed,
            main,
            aux,
            quotient: compiled.quotient_width,
        };

        for (name, derived, actual) in [
            (
                "preprocessed",
                geometry.preprocessed.iter().sum::<usize>(),
                layout.counts.preprocessed_width,
            ),
            ("main", geometry.main.iter().sum::<usize>(), layout.counts.width),
            (
                "auxiliary-coordinate",
                geometry.aux.iter().sum::<usize>(),
                layout.counts.aux_width * EXT_DEGREE,
            ),
            (
                "auxiliary-boundary",
                aux_values.iter().sum::<usize>(),
                layout.counts.num_aux_boundary,
            ),
        ] {
            if derived != actual {
                return Err(format!(
                    "chiplet-derived {name} width {derived} disagrees with the PVM ACE input \
                     layout width {actual}"
                ));
            }
        }

        // The row the hook pipes must be exactly the row the circuit reads.
        let current = layout
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .ok_or_else(|| "PVM ACE layout is missing the current-row start".to_string())?;
        let next = layout
            .index(InputKey::Preprocessed { offset: 1, index: 0 })
            .ok_or_else(|| "PVM ACE layout is missing the next-row start".to_string())?;
        let layout_felts = next
            .checked_sub(current)
            .and_then(|slots| slots.checked_mul(EXT_DEGREE))
            .ok_or_else(|| "PVM next-row boundary precedes the current row".to_string())?;
        if layout_felts != geometry.row_felts() {
            return Err(format!(
                "the PVM ACE layout has {layout_felts} felts per out-of-domain row but the \
                 chiplet widths require {}",
                geometry.row_felts()
            ));
        }
        if !geometry.row_felts().is_multiple_of(ADV_PIPE_BLOCK_FELTS) {
            return Err(format!(
                "the PVM out-of-domain row is {} felts, which is not {ADV_PIPE_BLOCK_FELTS}-felt \
                 aligned",
                geometry.row_felts()
            ));
        }

        Ok(geometry)
    }

    /// Felts in one out-of-domain row.
    pub(crate) fn row_felts(&self) -> usize {
        let slots: usize = self.preprocessed.iter().sum::<usize>()
            + self.main.iter().sum::<usize>()
            + self.aux.iter().sum::<usize>()
            + self.quotient;
        slots * EXT_DEGREE
    }

    /// `adv_pipe` blocks in one out-of-domain row.
    #[cfg(test)]
    pub(crate) fn row_blocks(&self) -> usize {
        self.row_felts() / ADV_PIPE_BLOCK_FELTS
    }
}

// SCATTER PLAN
// ================================================================================================

/// Live ranges occupied within the out-of-domain scatter table.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PvmScatterTableLayout {
    /// `(row-relative destination, pipe digest address)` pairs for order-dependent segments.
    pub(crate) proof_order_pairs: Range<usize>,
    /// Procedure-digest words used to dispatch the distinct `pipe_k` lengths.
    pub(crate) pipe_digests: Range<usize>,
}

fn pvm_scatter_plan(geometry: &PvmOodGeometry) -> Result<OodScatterPlan, String> {
    let plan = OodScatterPlan::new(
        &geometry.preprocessed,
        &geometry.main,
        &geometry.aux,
        geometry.quotient,
    )
    .map_err(|err| err.to_string())?;
    if plan.table_felts() > OOD_SCATTER_TABLE_FELTS as usize {
        return Err(format!(
            "the PVM scatter table needs {} felts but OOD_SCATTER_TABLE_PTR reserves {OOD_SCATTER_TABLE_FELTS}",
            plan.table_felts()
        ));
    }
    Ok(plan)
}

/// Derives the occupied scatter-table ranges from the same plan that renders the ingest hook.
#[cfg(test)]
pub(crate) fn pvm_scatter_table_layout(
    geometry: &PvmOodGeometry,
) -> Result<PvmScatterTableLayout, String> {
    let plan = pvm_scatter_plan(geometry)?;
    Ok(PvmScatterTableLayout {
        proof_order_pairs: plan.proof_order_pairs(),
        pipe_digests: plan.pipe_digests(),
    })
}

// RENDERING
// ================================================================================================

/// Distinct pipe lengths used by every variant, in their compact digest-table order.
pub(crate) fn pvm_pipe_lengths() -> Vec<usize> {
    let mut lengths: Vec<_> = ChipletAir::all()
        .iter()
        .flat_map(|air| {
            [
                <ChipletAir as BaseAir<Felt>>::width(air).next_multiple_of(LMCS_ALIGNMENT),
                (<ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(air) * EXT_DEGREE)
                    .next_multiple_of(LMCS_ALIGNMENT),
            ]
        })
        .map(|width| width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS)
        .chain([2])
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

/// Renders shared OOD ingestion and the five possible proof-order sort networks.
pub(crate) fn render_pvm_ood_frames(
    geometry: &PvmOodGeometry,
    ids_word_aligned: bool,
) -> Result<String, String> {
    pvm_scatter_plan(geometry)?;
    let lengths = pvm_pipe_lengths();
    let mut out = format!(
        "# GENERATED by `{}` — do not edit by hand.\nuse {{LOG_AIR_TRACE_LENGTHS_PTR}} from miden::core::stark::constants\nuse miden::core::stark::types\nuse miden::core::sys::pvm::layout\n\n",
        crate::ace_constants::GENERATED_BY,
    );
    for blocks in &lengths {
        writeln!(out, "proc pipe_{blocks}\n    repeat.{blocks}\n        adv_pipe\n        horner_eval_ext\n        compress\n    end\nend\n").unwrap();
    }
    for count in 8..=NUM_CHIPLETS {
        let maps = render_proof_order_maps(&ProofOrderMapsConfig {
            num_airs: count,
            heights_ptr: "push.LOG_AIR_TRACE_LENGTHS_PTR",
            pos_by_id_ptr: "exec.layout::proof_order_positions_ptr",
            id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
            word_load_heights: false,
            word_store_ids: ids_word_aligned,
        })
        .map_err(|err| err.to_string())?;
        out.push_str(&maps.replace(
            "pub proc stage_proof_order_maps",
            &format!("proc stage_proof_order_maps_{count}"),
        ));
    }
    out.push_str("\npub proc stage_proof_order_maps()\n");
    for count in 8..NUM_CHIPLETS {
        writeln!(out, "    exec.layout::num_airs eq.{count}\n    if.true exec.stage_proof_order_maps_{count} else").unwrap();
    }
    out.push_str("    exec.stage_proof_order_maps_12\n");
    for _ in 8..NUM_CHIPLETS {
        out.push_str("    end\n");
    }
    out.push_str("end\n\npub proc stage_ood_scatter_table()\n");
    for (index, blocks) in lengths.iter().enumerate() {
        writeln!(out, "    procref.pipe_{blocks} exec.layout::ood_scatter_table_ptr add.{} mem_storew_le dropw", 52+4*index).unwrap();
    }
    out.push_str(
        r#"    exec.layout::ood_scatter_table_ptr add.4
    exec.layout::main_ood_pipe_offsets_ptr
    exec.layout::main_ood_offsets_ptr
    exec.stage_group
    exec.layout::ood_scatter_table_ptr add.4
    exec.layout::num_airs mul.2 add
    exec.layout::aux_ood_pipe_offsets_ptr
    exec.layout::aux_ood_offsets_ptr
    exec.stage_group
end

# Input: [offsets_ptr, pipe_offsets_ptr, slots_ptr]. Every source is trusted selected metadata.
proc stage_group
    push.0
    dup exec.layout::num_airs u32lt
    while.true
        dup exec.layout::proof_order_positions_ptr add mem_load mul.2 dup.4 add
        # [pair, i, offsets, pipe_offsets, slots]
        dup.1 dup.3 add mem_load
        dup.1 mem_store
        dup.1 dup.4 add mem_load exec.layout::ood_scatter_table_ptr add
        dup.1 add.1 mem_store
        drop add.1
        dup exec.layout::num_airs u32lt
    end
    drop drop drop drop
end

#! Absorbs proof-ordered OOD values while scattering them into canonical READ addresses.
pub proc process_row_ood_evaluations(
    state: types::EidosState,
    evaluation: types::HornerState,
) -> (types::EidosState, types::HornerState)
    dup.12 exec.layout::ood_scatter_table_ptr mem_store
    # BytePairLut is the sole preprocessed occupant in every variant.
    exec.pipe_2

"#,
    );
    // Every supported relation has at least eight AIRs. A shared unrolled prefix and four
    // guarded suffixes avoid carrying loop state through the full 16-cell pipe ABI.
    for position in 0..2 * NUM_CHIPLETS {
        if position >= 16 && position % 2 == 0 {
            writeln!(out, "    exec.layout::num_airs u32gt.{}\n    if.true", position / 2).unwrap();
        }
        writeln!(
            out,
            "    exec.layout::ood_scatter_table_ptr dup add.{} mem_load swap mem_load add\n    swap.13 drop\n    exec.layout::ood_scatter_table_ptr add.{} mem_load\n    dynexec",
            4 + 2 * position,
            5 + 2 * position,
        )
        .unwrap();
    }
    for _ in 8..NUM_CHIPLETS {
        out.push_str("    end\n");
    }
    out.push_str(
        r#"
    exec.layout::ood_scatter_table_ptr mem_load exec.layout::quotient_row_offset add
    swap.13 drop
    exec.pipe_2
    exec.layout::ood_scatter_table_ptr mem_load exec.layout::ood_row_felts add
    swap.13 drop
end
"#,
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_ace_codegen::LayoutKind;
    use miden_air_definitions::precompiles::{
        ace::build_canonical_precompile_ace_circuit, relation::CapturedPvmRelation,
    };

    use super::*;

    const HOOK_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/ood_frames.masm");

    pub(crate) fn live_geometry() -> PvmOodGeometry {
        let captured = CapturedPvmRelation::new().expect("captured PVM relation");
        let compiled = captured.compile().expect("compiled PVM relation");
        let canonical = compiled.build_circuit(LayoutKind::Masm).expect("PVM canonical circuit");
        PvmOodGeometry::from_compiled(compiled.geometry(), canonical.layout())
            .expect("PVM out-of-domain geometry")
    }

    /// Pins the per-chiplet row geometry and dispatch plan derived from the canonical circuit
    /// layout.
    #[test]
    fn pvm_row_geometry_is_the_one_the_hook_was_rendered_from() {
        let geometry = live_geometry();
        assert_eq!(geometry.preprocessed, vec![0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(geometry.main, vec![48, 112, 56, 8, 40, 48, 32, 24, 24, 40, 56, 40]);
        assert_eq!(geometry.aux, vec![16, 40, 16, 8, 16, 48, 8, 8, 16, 24, 16, 8]);
        assert_eq!(geometry.quotient, 8);
        assert_eq!(geometry.row_felts(), 1_536);
        assert_eq!(geometry.row_blocks(), 192);

        let plan = pvm_scatter_plan(&geometry).expect("scatter plan");
        assert_eq!(plan.segment_count(), 26, "one segment per occupied per-chiplet block");
        assert_eq!(plan.dispatched_slots(), 24, "main and aux are the order-dependent groups");
        assert_eq!(
            pvm_scatter_table_layout(&geometry).unwrap(),
            PvmScatterTableLayout {
                proof_order_pairs: 4..52,
                pipe_digests: 52..84,
            }
        );
    }

    /// The checked-in hook must be exactly what the current chiplet widths render.
    #[test]
    fn generated_pvm_ood_hook_is_up_to_date() {
        // The generated layout pads `pos_by_id` to a word, so `id_by_pos` is word-aligned.
        let rendered = render_pvm_ood_frames(&live_geometry(), true).expect("render the PVM hook");
        let checked_in = std::fs::read_to_string(HOOK_PATH)
            .unwrap_or_else(|err| panic!("failed to read {HOOK_PATH}: {err}"));
        assert_eq!(
            checked_in, rendered,
            "asm/sys/pvm/ood_frames.masm is stale; run `make regenerate-pvm-constants`"
        );
    }

    /// A group every chiplet occupies is indexed correctly by proof-order position, and one with a
    /// single occupant needs no table at all. Anything between the two would address past the
    /// group's slots, so the renderer must refuse it instead of emitting it.
    #[test]
    fn scatter_plan_rejects_partially_occupied_commitment_groups() {
        // A geometry whose only meaningful axis is the preprocessed occupancy under test: the
        // uniform main and aux widths keep the `pipe_k` set small enough that the reserve, which
        // this test is not about, never becomes the reason for a refusal.
        let with_preprocessed = |widths: Vec<usize>| PvmOodGeometry {
            preprocessed: widths,
            main: vec![32; NUM_CHIPLETS],
            aux: vec![8; NUM_CHIPLETS],
            quotient: 8,
        };

        // The PVM preprocessed commitment group is occupied only by `ChipletAir::BytePairLut`.
        assert!(pvm_scatter_plan(&live_geometry()).is_ok());
        let mut sole = vec![0usize; NUM_CHIPLETS];
        sole[3] = 16;
        assert!(pvm_scatter_plan(&with_preprocessed(sole)).is_ok());
        // Every chiplet occupies the group.
        assert!(pvm_scatter_plan(&with_preprocessed(vec![16; NUM_CHIPLETS])).is_ok());

        let mut partial = vec![0usize; NUM_CHIPLETS];
        partial[0] = 16;
        partial[3] = 16;
        let Err(error) = pvm_scatter_plan(&with_preprocessed(partial)) else {
            panic!("a partially occupied group must be refused");
        };
        assert!(
            error.contains("preprocessed commitment group is occupied by 2 of 12"),
            "unexpected refusal: {error}"
        );
    }

    /// The reserve is a fixed constant in the generated layout, so the renderer — not the
    /// verifier at run time — is what must notice when the plan outgrows it.
    #[test]
    fn scatter_plan_refuses_to_outgrow_the_reserved_table() {
        let base = live_geometry();
        // Give every chiplet a distinct main and aux width, so the `pipe_k` set grows a word at a
        // time until the digests no longer fit behind the twenty-four dispatch pairs.
        let geometry = PvmOodGeometry {
            preprocessed: base.preprocessed.clone(),
            main: (0..NUM_CHIPLETS).map(|i| 32 * (i + 1)).collect(),
            aux: (0..NUM_CHIPLETS).map(|i| 8 * (i + 1)).collect(),
            quotient: base.quotient,
        };
        let Err(error) = pvm_scatter_plan(&geometry) else {
            panic!("a plan past the reserve must be refused");
        };
        assert!(error.contains("OOD_SCATTER_TABLE_PTR reserves"), "unexpected refusal: {error}");
    }

    /// The row the hook pipes is the row the circuit reads; a drifted width must fail closed.
    #[test]
    fn geometry_derivation_cross_checks_the_input_layout() {
        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        let layout = canonical.layout();
        let captured = CapturedPvmRelation::new().expect("captured PVM relation");
        let compiled = captured.compile().expect("compiled PVM relation");
        let geometry =
            PvmOodGeometry::from_compiled(compiled.geometry(), layout).expect("geometry");
        assert_eq!(
            geometry.row_felts() / 2,
            layout.counts.preprocessed_width
                + layout.counts.width
                + layout.counts.aux_width * EXT_DEGREE
                + layout.counts.num_quotient_chunks * EXT_DEGREE,
            "the derived row is not the sum of the layout's own commitment groups"
        );
    }
}
