//! Geometry and MASM rendering of the PVM out-of-domain row hook.
//!
//! The proof commits each chiplet's trace at its position in the height-sorted proof order, while
//! the canonical ACE circuit reads that trace at the chiplet's instance-order offset. The gap is
//! closed at ingest: the transcript absorb and the DEEP Horner accumulation stay positional over
//! the advice stream, and only `adv_pipe`'s destination is retargeted at segment boundaries.
//!
//! Everything below is derived from [`ChipletAir::all`]'s widths, so a chiplet width change moves
//! the destinations, the `pipe_k` set and the dispatch table together.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Write as _, ops::Range};

use miden_ace_codegen::{
    EXT_DEGREE, InputKey, InputLayout, OodScatterPlan, ProofOrderMapsConfig,
    render_proof_order_maps,
};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::{ChipletAir, NUM_CHIPLETS};

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
    preprocessed: Vec<usize>,
    main: Vec<usize>,
    aux: Vec<usize>,
    /// Shared across chiplets: the quotient is one recomposed matrix, not a per-AIR one.
    quotient: usize,
}

impl PvmOodGeometry {
    /// Derives the row geometry from the chiplet declarations and cross-checks it against the
    /// circuit's own input layout.
    pub(crate) fn from_input_layout(layout: &InputLayout) -> Result<Self, String> {
        let airs = ChipletAir::all();
        let mut preprocessed = Vec::with_capacity(NUM_CHIPLETS);
        let mut main = Vec::with_capacity(NUM_CHIPLETS);
        let mut aux = Vec::with_capacity(NUM_CHIPLETS);
        let mut aux_values = Vec::with_capacity(NUM_CHIPLETS);
        for air in airs.iter() {
            preprocessed.push(
                <ChipletAir as BaseAir<Felt>>::preprocessed_width(air)
                    .next_multiple_of(LMCS_ALIGNMENT),
            );
            main.push(<ChipletAir as BaseAir<Felt>>::width(air).next_multiple_of(LMCS_ALIGNMENT));
            aux.push(
                (<ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(air) * EXT_DEGREE)
                    .next_multiple_of(LMCS_ALIGNMENT),
            );
            aux_values.push(<ChipletAir as LiftedAir<Felt, QuadFelt>>::num_aux_values(air));
        }
        if aux_values.as_slice() != [1usize; NUM_CHIPLETS].as_slice() {
            return Err(format!(
                "the PVM proof-order boundary scatter requires exactly one auxiliary value per \
                 chiplet, got {aux_values:?}"
            ));
        }
        let geometry = Self {
            preprocessed,
            main,
            aux,
            quotient: layout.counts.num_quotient_chunks * EXT_DEGREE,
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
    pub(crate) fn row_blocks(&self) -> usize {
        self.row_felts() / ADV_PIPE_BLOCK_FELTS
    }

    /// Committed-row widths and the MASM constants that bind their DEEP-query LMCS frames.
    ///
    /// These are base-field widths: auxiliary columns have already been expanded into extension
    /// coordinates above, while out-of-domain transport expands every evaluation once more in
    /// [`Self::row_felts`].
    #[cfg(feature = "constants-tools")]
    pub(crate) fn deep_query_groups(&self) -> [(&'static str, &'static str, usize); 4] {
        [
            (
                "PREPROCESSED_ROW_DOUBLE_WORDS",
                "PREPROCESSED_LMCS_INIT_CV",
                self.preprocessed.iter().sum(),
            ),
            ("MAIN_ROW_DOUBLE_WORDS", "MAIN_LMCS_INIT_CV", self.main.iter().sum()),
            ("AUX_ROW_DOUBLE_WORDS", "AUX_LMCS_INIT_CV", self.aux.iter().sum()),
            ("QUOTIENT_ROW_DOUBLE_WORDS", "QUOTIENT_LMCS_INIT_CV", self.quotient),
        ]
    }
}

// SCATTER PLAN
// ================================================================================================

/// Live ranges occupied within the out-of-domain scatter table.
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
#[cfg(feature = "constants-tools")]
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

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

/// Renders `asm/sys/pvm/ood_frames.masm` from the chiplet widths.
///
/// `ids_word_aligned` states whether the `id_by_pos` table starts on a word boundary, which lets
/// the proof-order pass write complete groups of four IDs with word stores.
pub(crate) fn render_pvm_ood_frames(
    geometry: &PvmOodGeometry,
    ids_word_aligned: bool,
) -> Result<String, String> {
    let plan = pvm_scatter_plan(geometry)?;
    let row_felts = geometry.row_felts();
    let row_blocks = geometry.row_blocks();
    let proof_order_maps = render_proof_order_maps(&ProofOrderMapsConfig {
        num_airs: NUM_CHIPLETS,
        heights_ptr: "exec.constants::air_trace_length_logs_ptr",
        pos_by_id_ptr: "exec.layout::proof_order_positions_ptr",
        id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
        // Ten heights do not form a single word and are read once per proof.
        word_load_heights: false,
        word_store_ids: ids_word_aligned,
    })
    .map_err(|err| err.to_string())?;

    let procedures = plan.render(&proof_order_maps);

    let mut out = String::new();
    write!(
        out,
        r#"# GENERATED by `{generated_by}` — do not edit by hand.
use miden::core::stark::constants
use miden::core::stark::types
use miden::core::sys::pvm::layout

# Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
#   preprocessed: {preprocessed_parts} = {preprocessed} scalar evaluations
#   main:         {main_parts} = {main} scalar evaluations
#   aux:          {aux_parts} = {aux} scalar evaluations
#   quotient:     {quotient} scalar evaluations
# The advice stream supplies {row_felts} base felts, read as {row_blocks} `adv_pipe` blocks,
# split into {segments} segments ({dispatched} of them order-dependent).

{procedures}"#,
        generated_by = crate::ace_constants::GENERATED_BY,
        preprocessed_parts = format_sum(&geometry.preprocessed),
        preprocessed = geometry.preprocessed.iter().sum::<usize>(),
        main_parts = format_sum(&geometry.main),
        main = geometry.main.iter().sum::<usize>(),
        aux_parts = format_sum(&geometry.aux),
        aux = geometry.aux.iter().sum::<usize>(),
        quotient = geometry.quotient,
        segments = plan.segment_count(),
        dispatched = plan.dispatched_slots(),
    )
    .expect("writing to String cannot fail");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::ace::build_canonical_precompile_ace_circuit;

    const HOOK_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/ood_frames.masm");

    pub(crate) fn live_geometry() -> PvmOodGeometry {
        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        PvmOodGeometry::from_input_layout(canonical.layout()).expect("PVM out-of-domain geometry")
    }

    /// Pins the per-chiplet row geometry and dispatch plan derived from the canonical circuit
    /// layout.
    #[test]
    fn pvm_row_geometry_is_the_one_the_hook_was_rendered_from() {
        let geometry = live_geometry();
        assert_eq!(geometry.preprocessed, vec![0, 0, 0, 8, 0, 0, 0, 0, 0, 0]);
        assert_eq!(geometry.main, vec![104, 112, 72, 8, 40, 48, 32, 24, 24, 48]);
        assert_eq!(geometry.aux, vec![40, 40, 24, 8, 24, 56, 8, 16, 24, 32]);
        assert_eq!(geometry.quotient, 8);
        assert_eq!(geometry.row_felts(), 1_600);
        assert_eq!(geometry.row_blocks(), 200);

        let plan = pvm_scatter_plan(&geometry).expect("scatter plan");
        assert_eq!(plan.segment_count(), 22, "one segment per occupied per-chiplet block");
        assert_eq!(plan.dispatched_slots(), 20, "main and aux are the order-dependent groups");
        assert_eq!(
            pvm_scatter_table_layout(&geometry).unwrap(),
            PvmScatterTableLayout {
                proof_order_pairs: 4..44,
                pipe_digests: 44..84,
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
            error.contains("preprocessed commitment group is occupied by 2 of 10"),
            "unexpected refusal: {error}"
        );
    }

    /// The reserve is a fixed constant in the generated layout, so the renderer — not the
    /// verifier at run time — is what must notice when the plan outgrows it.
    #[test]
    fn scatter_plan_refuses_to_outgrow_the_reserved_table() {
        let base = live_geometry();
        // Give every chiplet a distinct main and aux width, so the `pipe_k` set grows a word at a
        // time until the digests no longer fit behind the twenty dispatch pairs.
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
        assert!(PvmOodGeometry::from_input_layout(layout).is_ok());
        assert_eq!(
            PvmOodGeometry::from_input_layout(layout).expect("geometry").row_felts() / 2,
            layout.counts.preprocessed_width
                + layout.counts.width
                + layout.counts.aux_width * EXT_DEGREE
                + layout.counts.num_quotient_chunks * EXT_DEGREE,
            "the derived row is not the sum of the layout's own commitment groups"
        );
    }
}
