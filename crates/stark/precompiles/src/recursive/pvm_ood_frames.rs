//! Geometry and MASM rendering of the PVM out-of-domain row hook.
//!
//! The proof commits each chiplet's trace at its position in the height-sorted proof order, while
//! the canonical ACE circuit reads that trace at the chiplet's instance-order offset. The gap is
//! closed at ingest: the transcript absorb and the DEEP Horner accumulation stay positional over
//! the advice stream, and only `adv_pipe`'s destination is retargeted at segment boundaries.
//!
//! Chiplet widths determine the canonical destinations, `pipe_k` procedures, and dispatch records.
//! The generator derives all three from the same compiled geometry.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write as _;

use miden_ace::{
    EXT_DEGREE, InputLayout,
    compiler::{OodScatterPlan, RelationGeometry, render_proof_order_maps},
};
use miden_air::precompiles::NUM_CHIPLETS;

/// Per-AIR trace regions are padded to this width before concatenation into a commitment group.
const LMCS_ALIGNMENT: usize = 8;

/// Felts moved by one `adv_pipe`.
///
/// This transport width governs block/segment arithmetic and destination alignment;
/// [`LMCS_ALIGNMENT`] independently governs column-padding widths.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

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
    /// Derives the row geometry from the compiled relation's chiplet widths and cross-checks it
    /// against the circuit's own input layout.
    pub(crate) fn from_compiled(
        compiled: &RelationGeometry,
        layout: &InputLayout,
    ) -> Result<Self, String> {
        compiled.validate_masm_layout(layout).map_err(|err| err.to_string())?;
        if compiled.airs.len() != NUM_CHIPLETS {
            return Err(format!(
                "compiled PVM relation has {} AIRs, expected {NUM_CHIPLETS}",
                compiled.airs.len()
            ));
        }
        Ok(Self {
            preprocessed: compiled.airs.iter().map(|air| air.preprocessed.width).collect(),
            main: compiled.airs.iter().map(|air| air.main.width).collect(),
            aux: compiled.airs.iter().map(|air| air.aux.width).collect(),
            quotient: compiled.quotient_width,
        })
    }

    /// Base-field felts in the scratch row used for one authenticated query opening.
    pub(crate) fn query_row_felts(&self) -> usize {
        self.preprocessed.iter().sum::<usize>()
            + self.main.iter().sum::<usize>()
            + self.aux.iter().sum::<usize>()
            + self.quotient
    }

    /// Felts in one out-of-domain row.
    pub(crate) fn row_felts(&self) -> usize {
        self.query_row_felts() * EXT_DEGREE
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

pub(crate) fn pvm_scatter_plan(geometry: &PvmOodGeometry) -> Result<OodScatterPlan, String> {
    OodScatterPlan::new(&geometry.preprocessed, &geometry.main, &geometry.aux, geometry.quotient)
        .map_err(|err| err.to_string())
}

// RENDERING
// ================================================================================================

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

/// Renders `asm/sys/pvm/ood_frames.masm` from the chiplet widths.
pub(crate) fn render_pvm_ood_frames(geometry: &PvmOodGeometry) -> Result<String, String> {
    let plan = pvm_scatter_plan(geometry)?;
    let row_felts = geometry.row_felts();
    let row_blocks = geometry.row_blocks();
    let proof_order_maps = render_proof_order_maps(NUM_CHIPLETS).map_err(|err| err.to_string())?;

    let procedures = plan.render(&proof_order_maps);

    let mut out = String::new();
    write!(
        out,
        r#"# GENERATED by `{generated_by}` — do not edit by hand.
use {{
    LOG_AIR_TRACE_LENGTHS_PTR,
    OOD_SCATTER_TABLE_PTR,
    PROOF_ORDER_IDS_PTR,
    PROOF_ORDER_POSITIONS_PTR,
}} from miden::core::stark::constants
use miden::core::stark::types

# Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
#   preprocessed: {preprocessed_parts} = {preprocessed} scalar evaluations
#   main:         {main_parts} = {main} scalar evaluations
#   aux:          {aux_parts} = {aux} scalar evaluations
#   quotient:     {quotient} scalar evaluations
# The advice stream supplies {row_felts} base felts, read as {row_blocks} `adv_pipe` blocks,
# split into {segments} segments ({dispatched} of them order-dependent).

{procedures}"#,
        generated_by = crate::recursive::ace_constants::GENERATED_BY,
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

    use miden_ace::compiler::LayoutKind;
    use miden_air_definitions::compiler::precompiles::{
        CapturedPvmRelation, build_canonical_precompile_ace_circuit,
    };

    use super::*;

    const HOOK_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../lib/core/asm/sys/pvm/ood_frames.masm");

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
        assert_eq!(geometry.main, vec![48, 104, 56, 8, 40, 48, 32, 24, 24, 40, 56, 40]);
        assert_eq!(geometry.aux, vec![16, 40, 16, 8, 16, 48, 8, 8, 16, 24, 16, 8]);
        assert_eq!(geometry.quotient, 8);
        assert_eq!(geometry.row_felts(), 1_520);
        assert_eq!(geometry.row_blocks(), 190);

        let plan = pvm_scatter_plan(&geometry).expect("scatter plan");
        assert_eq!(plan.segment_count(), 26, "one segment per occupied per-chiplet block");
        assert_eq!(plan.dispatched_slots(), 24, "main and aux are the order-dependent groups");
        assert_eq!(plan.proof_order_pairs(), 4..52);
        assert_eq!(plan.pipe_digests(), 52..84);
    }

    /// The checked-in hook must be exactly what the current chiplet widths render.
    #[test]
    fn generated_pvm_ood_hook_is_up_to_date() {
        let rendered = render_pvm_ood_frames(&live_geometry()).expect("render the PVM hook");
        let checked_in = std::fs::read_to_string(HOOK_PATH)
            .unwrap_or_else(|err| panic!("failed to read {HOOK_PATH}: {err}"));
        assert_eq!(
            checked_in, rendered,
            "asm/sys/pvm/ood_frames.masm is stale; run `make regenerate-pvm-constants`"
        );
    }

    /// A group every chiplet occupies is indexed correctly by proof-order position, and one with a
    /// single occupant needs no dispatch record. Anything between the two would address past the
    /// group's slots, so the renderer must refuse it instead of emitting it.
    #[test]
    fn scatter_plan_rejects_partially_occupied_commitment_groups() {
        // A single auxiliary occupant keeps the plan to at most two dispatched groups, so the
        // fixed reserve fits even when every chiplet occupies the preprocessed group.
        let with_preprocessed = |widths: Vec<usize>| PvmOodGeometry {
            preprocessed: widths,
            main: vec![32; NUM_CHIPLETS],
            aux: [vec![8], vec![0; NUM_CHIPLETS - 1]].concat(),
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

        // A stale group, statement prefix, boundary count, or quotient shape must fail before
        // generating addresses or emitting a different number of advice reads.
        for counts in [
            miden_ace::InputCounts {
                width: layout.counts.width + 8,
                ..layout.counts
            },
            miden_ace::InputCounts {
                aux_width: layout.counts.aux_width + 4,
                ..layout.counts
            },
            miden_ace::InputCounts {
                num_public: layout.counts.num_public + 4,
                ..layout.counts
            },
            miden_ace::InputCounts {
                num_aux_boundary: NUM_CHIPLETS - 1,
                ..layout.counts
            },
            miden_ace::InputCounts {
                num_quotient_chunks: layout.counts.num_quotient_chunks + 1,
                ..layout.counts
            },
        ] {
            let mut stale = layout.clone();
            stale.counts = counts;
            assert!(PvmOodGeometry::from_compiled(compiled.geometry(), &stale).is_err());
        }
        let mut truncated = layout.clone();
        truncated.total_inputs = 0;
        assert!(PvmOodGeometry::from_compiled(compiled.geometry(), &truncated).is_err());
        let mut unsupported = compiled.geometry().clone();
        unsupported.airs[0].num_aux_boundary = 2;
        assert!(PvmOodGeometry::from_compiled(&unsupported, layout).is_err());
    }
}
