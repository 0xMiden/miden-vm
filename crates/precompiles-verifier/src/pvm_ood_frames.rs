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
use core::fmt::Write as _;

use miden_ace_codegen::{EXT_DEGREE, InputKey, InputLayout};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::{ChipletAir, NUM_CHIPLETS};

/// Per-AIR trace regions are padded to this width before concatenation into a commitment group.
const LMCS_ALIGNMENT: usize = 8;

/// Felts moved by one `adv_pipe`. Numerically equal to [`LMCS_ALIGNMENT`] today, but a distinct
/// quantity: this bounds block/segment arithmetic and `adv_pipe` destination alignment, while
/// `LMCS_ALIGNMENT` bounds column-padding widths. If the two ever diverge, block arithmetic must
/// keep using this constant, not the padding width.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Felts reserved for the out-of-domain scatter table by `sys/pvm/layout.masm`.
pub(crate) const OOD_SCATTER_TABLE_FELTS: u32 = 96;

/// Offset, in felts from the table base, of the first `(destination, digest address)` pair.
const OOD_SCATTER_SLOTS_OFFSET: usize = 4;

const WORD_FELTS: usize = 4;

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

    fn groups(&self) -> [(&'static str, &Vec<usize>); 3] {
        [("preprocessed", &self.preprocessed), ("main", &self.main), ("aux", &self.aux)]
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
}

// SCATTER PLAN
// ================================================================================================

/// One per-chiplet segment of one commitment group, together with how the hook reaches it.
struct ScatterDispatch {
    group: &'static str,
    /// Canonical destination, in felts from the row base.
    dst: usize,
    /// Segment length in `adv_pipe` blocks.
    blocks: usize,
    /// Position of this segment within its commitment group on the wire.
    position: usize,
    /// Stream position in the runtime table, or `None` when the geometry fixes the segment's
    /// place on the wire regardless of the proof order.
    slot: Option<usize>,
}

/// Where chiplet `air`'s segment of one commitment group must land, and which table slot names it.
struct ScatterSource {
    group: &'static str,
    air: usize,
    dst: usize,
    blocks: usize,
    slot_offset: usize,
}

/// Compile-time shape of the out-of-domain ingest scatter.
struct ScatterPlan {
    dispatches: Vec<ScatterDispatch>,
    sources: Vec<ScatterSource>,
    /// Distinct segment lengths, ascending; one `pipe_k` procedure each.
    lengths: Vec<usize>,
    /// Offset, in felts from the table base, of the first `pipe_k` digest word.
    digest_offset: usize,
}

impl ScatterPlan {
    /// Felt offset from the table base of the `pipe_k` digest covering `blocks`.
    fn digest_offset_for(&self, blocks: usize) -> usize {
        let index = self
            .lengths
            .iter()
            .position(|length| *length == blocks)
            .expect("every segment length has a pipe procedure");
        self.digest_offset + WORD_FELTS * index
    }

    /// Number of segments the proof order can move.
    fn dispatched_slots(&self) -> usize {
        self.dispatches.iter().filter(|dispatch| dispatch.slot.is_some()).count()
    }
}

/// Derives the scatter's compile-time shape from the chiplet widths.
///
/// A commitment group holding at most one non-empty segment carries no proof-order freedom: its
/// occupant is always alone on the wire and always lands at the same canonical address, so it is
/// dispatched directly rather than through the table. The quotient matrix is relation-wide, not
/// per-chiplet, and is likewise fixed.
fn pvm_scatter_plan(geometry: &PvmOodGeometry) -> Result<ScatterPlan, String> {
    let mut dispatches = Vec::new();
    let mut sources = Vec::new();
    let mut group_base = 0usize;
    let mut slot = 0usize;

    for (group, widths) in geometry.groups() {
        let occupied = widths.iter().filter(|width| **width > 0).count();
        // Slots of one group are contiguous and indexed by proof position, so every source in the
        // group shares this base and adds `2 * pos` at run time. `pos` ranks the chiplet among
        // *all* chiplets, which indexes the group's slots only when every chiplet occupies the
        // group. A partially occupied group would need the rank among occupants instead, which
        // the proof order does not directly give; refuse to emit rather than silently address
        // past the group's slots.
        if occupied > 1 && occupied != widths.len() {
            return Err(format!(
                "the {group} commitment group is occupied by {occupied} of {} chiplets; the \
                 out-of-domain scatter indexes its table by proof-order position, which requires \
                 every chiplet to occupy the group",
                widths.len()
            ));
        }
        let group_slot_offset = OOD_SCATTER_SLOTS_OFFSET + 2 * slot;
        let mut canonical = group_base;
        let mut position = 0usize;
        for (air, width) in widths.iter().enumerate() {
            if *width == 0 {
                continue;
            }
            let blocks = width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS;
            if occupied > 1 {
                sources.push(ScatterSource {
                    group,
                    air,
                    dst: canonical,
                    blocks,
                    slot_offset: group_slot_offset,
                });
                dispatches.push(ScatterDispatch {
                    group,
                    dst: canonical,
                    blocks,
                    position,
                    slot: Some(slot),
                });
                slot += 1;
            } else {
                dispatches.push(ScatterDispatch {
                    group,
                    dst: canonical,
                    blocks,
                    position,
                    slot: None,
                });
            }
            position += 1;
            canonical += width * EXT_DEGREE;
        }
        group_base += widths.iter().sum::<usize>() * EXT_DEGREE;
    }
    dispatches.push(ScatterDispatch {
        group: "quotient",
        dst: group_base,
        position: 0,
        blocks: geometry.quotient * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
        slot: None,
    });

    // `adv_pipe` writes double words, so every retargeted destination must stay aligned.
    if let Some(bad) = dispatches.iter().find(|d| !d.dst.is_multiple_of(ADV_PIPE_BLOCK_FELTS)) {
        return Err(format!(
            "the {} segment at row offset {} is not {ADV_PIPE_BLOCK_FELTS}-felt aligned, which \
             `adv_pipe` requires of its destination",
            bad.group, bad.dst
        ));
    }

    let mut lengths: Vec<_> = dispatches.iter().map(|dispatch| dispatch.blocks).collect();
    lengths.sort_unstable();
    lengths.dedup();

    // Digest words must be word-aligned, so they follow the pair table at the next word boundary.
    let digest_offset = (OOD_SCATTER_SLOTS_OFFSET + 2 * slot).next_multiple_of(WORD_FELTS);
    let required = digest_offset + WORD_FELTS * lengths.len();
    if required > OOD_SCATTER_TABLE_FELTS as usize {
        return Err(format!(
            "the PVM out-of-domain scatter table needs {required} felts but \
             OOD_SCATTER_TABLE_PTR reserves {OOD_SCATTER_TABLE_FELTS}"
        ));
    }
    if dispatches.iter().map(|dispatch| dispatch.blocks).sum::<usize>() != geometry.row_blocks() {
        return Err("the PVM scatter dispatch table does not cover exactly one out-of-domain row"
            .to_string());
    }

    Ok(ScatterPlan {
        dispatches,
        sources,
        lengths,
        digest_offset,
    })
}

// RENDERING
// ================================================================================================

/// Emits `push.OFFSET`-free addressing of one table cell, leaving its value on the stack.
fn scatter_cell_load(offset: usize) -> String {
    if offset == 0 {
        "exec.layout::ood_scatter_table_ptr mem_load".into()
    } else {
        format!("exec.layout::ood_scatter_table_ptr add.{offset} mem_load")
    }
}

/// Loads one chiplet's staged proof-order position, leaving it on the stack.
fn scatter_position_load(air: usize) -> String {
    if air == 0 {
        "exec.layout::proof_order_positions_ptr mem_load".into()
    } else {
        format!("exec.layout::proof_order_positions_ptr add.{air} mem_load")
    }
}

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

/// Renders `asm/sys/pvm/ood_frames.masm` from the chiplet widths.
pub(crate) fn render_pvm_ood_frames(geometry: &PvmOodGeometry) -> Result<String, String> {
    let plan = pvm_scatter_plan(geometry)?;
    let row_felts = geometry.row_felts();
    let row_blocks = geometry.row_blocks();

    let pipes = plan
        .lengths
        .iter()
        .map(|blocks| {
            format!(
                "#! Absorbs {blocks} advice blocks into the row already targeted by the caller.\n\
                 #!\n\
                 #! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]\n\
                 #! Outputs: [scratch0, scratch1, cv', ptr + {felts}, alpha_ptr, acc0', acc1']\n\
                 proc pipe_{blocks}\n    \
                 repeat.{blocks}\n        \
                 adv_pipe\n        \
                 horner_eval_ext\n        \
                 compress\n    \
                 end\nend\n",
                felts = blocks * ADV_PIPE_BLOCK_FELTS,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let digest_staging = plan
        .lengths
        .iter()
        .map(|blocks| {
            format!(
                "    procref.pipe_{blocks} exec.layout::ood_scatter_table_ptr add.{offset} \
                 mem_storew_le dropw",
                offset = plan.digest_offset_for(*blocks),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut order_pass = Vec::new();
    for air in 0..NUM_CHIPLETS {
        let sources: Vec<_> = plan.sources.iter().filter(|source| source.air == air).collect();
        if sources.is_empty() {
            continue;
        }
        let mut block =
            format!("\n    {position}\n    # => [pos]\n", position = scatter_position_load(air),);
        for source in sources {
            block += &format!(
                "    # {group}: {blocks} blocks at row offset {dst}\n    \
                 push.{dst} dup.1 mul.2 exec.layout::ood_scatter_table_ptr add add.{slot} \
                 mem_store\n    \
                 exec.layout::ood_scatter_table_ptr add.{digest} dup.1 mul.2 \
                 exec.layout::ood_scatter_table_ptr add add.{next} mem_store\n",
                group = source.group,
                blocks = source.blocks,
                dst = source.dst,
                slot = source.slot_offset,
                digest = plan.digest_offset_for(source.blocks),
                next = source.slot_offset + 1,
            );
        }
        block += "    drop\n";
        order_pass.push(block);
    }

    let ingest = plan
        .dispatches
        .iter()
        .map(|dispatch| match dispatch.slot {
            // The proof order decides which chiplet sits here, so both the destination and the
            // segment length come from the table the order pass filled.
            Some(slot) => format!(
                "    # {group} group, proof position {position}\n    \
                 exec.layout::ood_scatter_table_ptr dup add.{pair} mem_load swap mem_load \
                 add\n    swap.13 drop\n    {digest}\n    dynexec",
                group = dispatch.group,
                position = dispatch.position,
                pair = OOD_SCATTER_SLOTS_OFFSET + 2 * slot,
                digest = scatter_cell_load(OOD_SCATTER_SLOTS_OFFSET + 2 * slot + 1),
            ),
            None => format!(
                "    # {group} group, sole occupant: {blocks} blocks at row offset {dst}\n    \
                 exec.layout::ood_scatter_table_ptr mem_load{offset}\n    swap.13 drop\n    \
                 exec.pipe_{blocks}",
                group = dispatch.group,
                dst = dispatch.dst,
                offset = if dispatch.dst == 0 {
                    String::new()
                } else {
                    format!(" add.{}", dispatch.dst)
                },
                blocks = dispatch.blocks,
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut out = String::new();
    write!(
        out,
        r#"# GENERATED by `{generated_by}` — do not edit by hand.
use miden::core::sys::pvm::layout

# Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
#   preprocessed: {preprocessed_parts} = {preprocessed} scalar evaluations
#   main:         {main_parts} = {main} scalar evaluations
#   aux:          {aux_parts} = {aux} scalar evaluations
#   quotient:     {quotient} scalar evaluations
# The advice stream supplies {row_felts} base felts, read as {row_blocks} `adv_pipe` blocks,
# split into {segments} segments ({dispatched} of them order-dependent).

{pipes}
#! Stages the proof-order-dependent half of the out-of-domain scatter table.
#!
#! The proof commits each chiplet's trace at its position in the height-sorted proof order, while
#! the canonical constraint circuit reads it at the chiplet's instance offset. Both the canonical
#! destination and the segment length are compile-time per chiplet; this procedure only routes them
#! to the stream position the absorbed trace heights put that chiplet in.
#!
#! Must run after the AIR heights are stored and before the first out-of-domain row is ingested.
#!
#! Inputs:  []
#! Outputs: []
pub proc stage_ood_scatter_table
{digest_staging}
{order_pass}end

#! Processes one PVM row of out-of-domain evaluations, scattering it to canonical addresses.
#!
#! The row is the LMCS-aligned wire sequence used by the lifted PCS, in commitment-group order:
#!
#! - {preprocessed} preprocessed extension-field slots;
#! - {main} main extension-field slots across {num_airs} chiplets in proof order;
#! - {aux} auxiliary-coordinate extension-field slots across {num_airs} chiplets in proof order;
#! - {quotient} quotient extension-field slots.
#!
#! Each block is stored, folded into the DEEP fixed term with `horner_eval_ext`, and compressed
#! into the Eidos transcript. The absorb and the accumulation stay positional over the advice
#! stream; the only thing the proof order moves is where each segment is stored, which the table
#! staged by `stage_ood_scatter_table` supplies.
#!
#! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]
#! Outputs: [scratch0, scratch1, cv', ptr + {row_felts}, alpha_ptr, acc0', acc1']
pub proc process_row_ood_evaluations
    dup.12 exec.layout::ood_scatter_table_ptr mem_store
{ingest}
    exec.layout::ood_scatter_table_ptr mem_load add.{row_felts}
    swap.13 drop
end
"#,
        generated_by = crate::ace_constants::GENERATED_BY,
        num_airs = NUM_CHIPLETS,
        preprocessed_parts = format_sum(&geometry.preprocessed),
        preprocessed = geometry.preprocessed.iter().sum::<usize>(),
        main_parts = format_sum(&geometry.main),
        main = geometry.main.iter().sum::<usize>(),
        aux_parts = format_sum(&geometry.aux),
        aux = geometry.aux.iter().sum::<usize>(),
        quotient = geometry.quotient,
        segments = plan.dispatches.len(),
        dispatched = plan.dispatched_slots(),
        order_pass = order_pass.join(""),
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

    /// The measured row geometry, pinned so a chiplet width change surfaces here with the numbers
    /// the hook was rendered from rather than only as a byte diff.
    #[test]
    fn pvm_row_geometry_is_the_one_the_hook_was_rendered_from() {
        let geometry = live_geometry();
        assert_eq!(geometry.preprocessed, vec![0, 0, 0, 8, 0, 0, 0, 0, 0, 0]);
        assert_eq!(geometry.main, vec![104, 128, 72, 8, 40, 48, 32, 24, 24, 48]);
        assert_eq!(geometry.aux, vec![48, 40, 24, 8, 24, 56, 8, 16, 24, 32]);
        assert_eq!(geometry.quotient, 8);
        assert_eq!(geometry.row_felts(), 1_648);
        assert_eq!(geometry.row_blocks(), 206);

        let plan = pvm_scatter_plan(&geometry).expect("scatter plan");
        assert_eq!(plan.dispatches.len(), 22, "one segment per occupied per-chiplet block");
        assert_eq!(plan.dispatched_slots(), 20, "main and aux are the order-dependent groups");
        assert_eq!(plan.lengths, vec![2, 4, 6, 8, 10, 12, 14, 18, 26, 32]);
        assert_eq!(plan.digest_offset, 44);
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

        // Today's shape: only BytePairAnd8 has preprocessed columns.
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
