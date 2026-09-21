//! OOD scatter planning and MASM procedure generation shared by VM and PVM verifiers.

use core::{fmt::Write, ops::Range};

use crate::{AceError, EXT_DEGREE};

const ADV_PIPE_BLOCK_FELTS: usize = 8;
const WORD_FELTS: usize = 4;
// The first word holds the active row pointer; dispatch pairs follow it.
const OOD_SCATTER_SLOTS_OFFSET: usize = 4;

struct ScatterSegment {
    /// Canonical destination, in felts from the row base.
    dst: usize,
    /// Segment length in `adv_pipe` blocks.
    blocks: usize,
}

struct ScatterGroup {
    name: &'static str,
    /// Nonempty segments in canonical row order.
    segments: Vec<ScatterSegment>,
    /// First dispatch slot, or `None` for a group with at most one occupant.
    /// Dispatched groups have one segment per AIR and one slot per proof position.
    slot_start: Option<usize>,
}

/// Canonical row destinations and proof-order dispatch slots for OOD evaluations.
pub struct OodScatterPlan {
    num_airs: usize,
    row_felts: usize,
    groups: Vec<ScatterGroup>,
    /// Distinct segment lengths, ascending; one `pipe_k` procedure each.
    lengths: Vec<usize>,
}

impl OodScatterPlan {
    /// Plans the preprocessed, main, auxiliary, and quotient commitment groups in wire order.
    ///
    /// Per-AIR widths are in canonical instance order and count extension-field evaluations,
    /// including trace padding. The three slices must describe the same nonempty AIR set.
    /// A per-AIR group may be empty, have one occupant, or contain every AIR. The quotient
    /// segment must be nonempty. All segments must fill whole 8-felt `adv_pipe` blocks,
    /// and the total row length must fit in a u32 address offset.
    pub fn new(
        preprocessed: &[usize],
        main: &[usize],
        aux: &[usize],
        quotient_width: usize,
    ) -> Result<Self, AceError> {
        let num_airs = main.len();
        if num_airs == 0 || preprocessed.len() != num_airs || aux.len() != num_airs {
            return Err(AceError::InvalidInputLayout {
                message: "scatter groups must describe the same nonempty AIR set".into(),
            });
        }
        if quotient_width == 0 {
            return Err(AceError::InvalidInputLayout {
                message: "the quotient scatter segment must be nonempty".into(),
            });
        }
        let widths = || preprocessed.iter().chain(main).chain(aux).chain([&quotient_width]);
        if widths().any(|width| !width.is_multiple_of(ADV_PIPE_BLOCK_FELTS / EXT_DEGREE)) {
            return Err(AceError::InvalidInputLayout {
                message: "scatter segments must be 8-felt aligned".into(),
            });
        }
        let row_felts = widths()
            .try_fold(0usize, |total, width| total.checked_add(*width))
            .and_then(|total| total.checked_mul(EXT_DEGREE))
            .filter(|&total| u32::try_from(total).is_ok())
            .ok_or_else(|| AceError::InvalidInputLayout {
                message: "the OOD row length must fit in a u32 address offset".into(),
            })?;

        let mut groups = Vec::with_capacity(4);
        let mut dst = 0;
        let mut slots = 0;
        for (name, widths) in [("preprocessed", preprocessed), ("main", main), ("aux", aux)] {
            let occupied = widths.iter().filter(|&&width| width != 0).count();
            // Proof positions rank all AIRs. A partially occupied group would need ranks
            // among its occupants to index its dispatch slots.
            if occupied > 1 && occupied != num_airs {
                return Err(AceError::InvalidInputLayout {
                    message: format!(
                        "the {name} commitment group is occupied by {occupied} of {num_airs} AIRs; \
                         dispatch by proof position requires every AIR to occupy the group",
                    ),
                });
            }
            let slot_start = if occupied > 1 {
                let start = slots;
                slots += num_airs;
                Some(start)
            } else {
                None
            };
            let segments = widths
                .iter()
                .filter(|&&width| width != 0)
                .map(|&width| {
                    let felts = width * EXT_DEGREE;
                    let segment = ScatterSegment {
                        dst,
                        blocks: felts / ADV_PIPE_BLOCK_FELTS,
                    };
                    dst += felts;
                    segment
                })
                .collect();
            groups.push(ScatterGroup { name, segments, slot_start });
        }
        groups.push(ScatterGroup {
            name: "quotient",
            segments: vec![ScatterSegment {
                dst,
                blocks: quotient_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
            }],
            slot_start: None,
        });
        let mut lengths: Vec<_> = groups
            .iter()
            .flat_map(|group| group.segments.iter().map(|segment| segment.blocks))
            .collect();
        lengths.sort_unstable();
        lengths.dedup();
        Ok(Self { num_airs, row_felts, groups, lengths })
    }

    /// Number of nonempty segments in each wire row.
    pub fn segment_count(&self) -> usize {
        self.groups.iter().map(|group| group.segments.len()).sum()
    }

    /// Number of wire segments whose destinations depend on proof order.
    pub fn dispatched_slots(&self) -> usize {
        self.groups.iter().filter(|group| group.slot_start.is_some()).count() * self.num_airs
    }

    /// Table-relative range of destination/digest-pointer pairs, in felts.
    pub fn proof_order_pairs(&self) -> Range<usize> {
        OOD_SCATTER_SLOTS_OFFSET..OOD_SCATTER_SLOTS_OFFSET + 2 * self.dispatched_slots()
    }

    /// Table-relative range of word-aligned procedure digests, in felts.
    pub fn pipe_digests(&self) -> Range<usize> {
        let start = self.proof_order_pairs().end.next_multiple_of(WORD_FELTS);
        start..start + WORD_FELTS * self.lengths.len()
    }

    /// Table space used by the row pointer, dispatch pairs and procedure digests, in felts.
    /// Relation-specific proof-order maps may follow this region or live elsewhere.
    pub fn table_felts(&self) -> usize {
        self.pipe_digests().end
    }

    fn digest_offset_for(&self, blocks: usize) -> usize {
        let index = self
            .lengths
            .iter()
            .position(|length| *length == blocks)
            .expect("every segment length has a pipe procedure");
        self.pipe_digests().start + WORD_FELTS * index
    }

    /// Renders pipe helpers, the supplied proof-order map pass, table staging, and OOD ingest.
    ///
    /// The enclosing MASM module must import `constants`, `types`, and its relation's `layout`.
    /// The layout supplies the scatter-table and proof-order map accessors.
    pub fn render(&self, proof_order_maps: &str) -> String {
        let mut out = String::new();
        for &blocks in &self.lengths {
            writeln!(
                out,
                r#"#! Absorbs {blocks} advice blocks at the destination supplied by the caller.
#!
#! Inputs:  [rate(8), cv(4), ptr, alpha_ptr, acc0, acc1]
#! Outputs: [rate'(8), cv'(4), ptr + {felts}, alpha_ptr, acc0', acc1']
proc pipe_{blocks}
    repeat.{blocks}
        adv_pipe
        horner_eval_ext
        compress
    end
end
"#,
                felts = blocks * ADV_PIPE_BLOCK_FELTS
            )
            .expect("writing to String cannot fail");
        }
        out.push_str(proof_order_maps);
        out.push_str(
            r#"
#! Stages canonical destinations and pipe-procedure addresses by proof position.
#!
#! Must run after `stage_proof_order_maps` and before ingesting the first OOD row.
#!
#! Inputs:  []
#! Outputs: []
#! Invocation: exec
pub proc stage_ood_scatter_table()
    exec.layout::ood_scatter_table_ptr
    # => [table]
"#,
        );
        for &blocks in &self.lengths {
            writeln!(
                out,
                "    procref.pipe_{blocks} dup.4 add.{offset} mem_storew_le dropw",
                offset = self.digest_offset_for(blocks)
            )
            .expect("writing to String cannot fail");
        }
        out.push_str("    exec.layout::proof_order_positions_ptr\n    # => [pos_ptr, table]\n");
        if self.dispatched_slots() != 0 {
            for air in 0..self.num_airs {
                writeln!(
                    out,
                    "\n    # AIR {air}: its pair slots start at table + 2 * pos_by_id[{air}]\n    \
                    {position} mul.2 dup.2 add\n    # => [base, pos_ptr, table]",
                    position = scatter_position_load(air)
                )
                .expect("writing to String cannot fail");
                for group in &self.groups {
                    let Some(slot_start) = group.slot_start else { continue };
                    let segment = &group.segments[air];
                    let slot = OOD_SCATTER_SLOTS_OFFSET + 2 * slot_start;
                    writeln!(
                        out,
                        "    # {group}: {blocks} blocks at row offset {dst}\n    \
                        push.{dst} dup.1 add.{slot} mem_store\n    \
                        dup.2 add.{digest} dup.1 add.{next} mem_store",
                        group = group.name,
                        blocks = segment.blocks,
                        dst = segment.dst,
                        digest = self.digest_offset_for(segment.blocks),
                        next = slot + 1,
                    )
                    .expect("writing to String cannot fail");
                }
                out.push_str("    drop\n");
            }
        }
        write!(
            out,
            r#"    drop drop
end

#! Loads one OOD row from advice and scatters it to canonical AIR addresses.
#!
#! The wire groups are preprocessed, main, auxiliary coordinates, and quotient. Each per-AIR
#! group arrives in proof order. Eidos absorption and DEEP Horner accumulation follow wire order;
#! the staged scatter table determines the memory destinations. The returned rate is the last
#! absorbed block. Call `stage_ood_scatter_table` before ingesting the first row.
#!
#! Inputs:  [rate(8), cv(4), ptr, alpha_ptr, acc0, acc1]
#! Outputs: [rate'(8), cv'(4), ptr + {row_felts}, alpha_ptr, acc0', acc1']
#! Invocation: exec
pub proc process_row_ood_evaluations(
    state: types::EidosState,
    evaluation: types::HornerState,
) -> (types::EidosState, types::HornerState)
    dup.12 exec.layout::ood_scatter_table_ptr mem_store
"#,
            row_felts = self.row_felts
        )
        .expect("writing to String cannot fail");
        for group in &self.groups {
            for (position, segment) in group.segments.iter().enumerate() {
                match group.slot_start {
                    Some(start) => {
                        let pair = OOD_SCATTER_SLOTS_OFFSET + 2 * (start + position);
                        writeln!(
                            out,
                            r#"    # {group} group, proof position {position}
    exec.layout::ood_scatter_table_ptr dup add.{pair} mem_load swap mem_load add
    swap.13 drop
    exec.layout::ood_scatter_table_ptr add.{digest} mem_load
    dynexec"#,
                            group = group.name,
                            digest = pair + 1,
                        )
                        .expect("writing to String cannot fail");
                    },
                    None => {
                        writeln!(
                            out,
                            r#"    # {group} group, sole occupant: {blocks} blocks at row offset {dst}
    exec.layout::ood_scatter_table_ptr mem_load{offset}
    swap.13 drop
    exec.pipe_{blocks}"#,
                            group = group.name,
                            blocks = segment.blocks,
                            dst = segment.dst,
                            offset = if segment.dst == 0 {
                                String::new()
                            } else {
                                format!(" add.{}", segment.dst)
                            },
                        )
                        .expect("writing to String cannot fail");
                    },
                }
            }
        }
        writeln!(
            out,
            "    exec.layout::ood_scatter_table_ptr mem_load add.{}\n    swap.13 drop\nend",
            self.row_felts
        )
        .expect("writing to String cannot fail");
        out
    }
}

/// Loads one AIR's staged proof-order position, leaving it on the stack.
fn scatter_position_load(air: usize) -> String {
    if air == 0 {
        "dup mem_load".into()
    } else {
        format!("dup add.{air} mem_load")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scatter_rejects_incomplete_or_unaddressable_rows() {
        assert!(OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 4).is_ok());
        assert!(OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 2).is_err());
        assert!(OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 0).is_err());
        // An incomplete segment also misaligns the next group's destination.
        assert!(OodScatterPlan::new(&[2, 0], &[4, 4], &[4, 4], 4).is_err());
        assert!(OodScatterPlan::new(&[0], &[usize::MAX - 3], &[0], 4).is_err());
        assert!(OodScatterPlan::new(&[0], &[1 << 31], &[0], 4).is_err());
    }
}
