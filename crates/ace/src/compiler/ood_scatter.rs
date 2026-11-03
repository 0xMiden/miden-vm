//! OOD scatter planning and MASM procedure generation shared by VM and PVM verifiers.

use core::{fmt::Write, ops::Range};

use crate::{AceError, EXT_DEGREE};

const ADV_PIPE_BLOCK_FELTS: usize = 8;
const WORD_FELTS: usize = 4;
// The first word holds the active row pointer; word-aligned dispatch records follow it.
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
    /// Index among dispatched groups, or `None` for a group with at most one occupant.
    /// Two consecutive dispatched groups share one record word per proof position.
    dispatch_index: Option<usize>,
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
        let mut dispatched_groups = 0;
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
            let dispatch_index = if occupied > 1 {
                let index = dispatched_groups;
                dispatched_groups += 1;
                Some(index)
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
            groups.push(ScatterGroup { name, segments, dispatch_index });
        }
        groups.push(ScatterGroup {
            name: "quotient",
            segments: vec![ScatterSegment {
                dst,
                blocks: quotient_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
            }],
            dispatch_index: None,
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
        self.groups.iter().filter(|group| group.dispatch_index.is_some()).count() * self.num_airs
    }

    /// Table-relative range of packed destination/digest-pointer records, in felts.
    ///
    /// Each word holds two dispatched groups' pairs for one proof position. Records for the
    /// first two groups precede those for the next two. An unpaired group uses zero padding
    /// for its word's second pair; that padding is included in the range.
    pub fn proof_order_pairs(&self) -> Range<usize> {
        let groups = self.dispatched_slots() / self.num_airs;
        OOD_SCATTER_SLOTS_OFFSET
            ..OOD_SCATTER_SLOTS_OFFSET + WORD_FELTS * self.num_airs * groups.div_ceil(2)
    }

    /// Table-relative range of word-aligned procedure digests, in felts.
    pub fn pipe_digests(&self) -> Range<usize> {
        let start = self.proof_order_pairs().end.next_multiple_of(WORD_FELTS);
        start..start + WORD_FELTS * self.lengths.len()
    }

    /// Table space used by the row pointer, dispatch pairs and procedure digests, in felts.
    /// The proof-order maps occupy separate shared arrays.
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

    /// Renders pipe helpers, the supplied proof-order pass, table staging, and OOD ingest.
    ///
    /// The enclosing module imports `types`, `OOD_SCATTER_TABLE_PTR` and
    /// `PROOF_ORDER_POSITIONS_PTR` from the shared STARK modules. The generator must check
    /// [`Self::table_felts`] against the shared scatter reservation before emitting the module.
    pub fn render(&self, proof_order_maps: &str) -> String {
        let mut out = String::new();
        for (record, offset) in self.proof_order_pairs().step_by(WORD_FELTS).enumerate() {
            writeln!(
                out,
                "const OOD_SCATTER_RECORD_{record}_PTR = OOD_SCATTER_TABLE_PTR + {offset}",
            )
            .expect("writing to String cannot fail");
        }
        out.push('\n');
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
    push.OOD_SCATTER_TABLE_PTR
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
        out.push_str("    push.PROOF_ORDER_POSITIONS_PTR\n    # => [pos_ptr, table]\n");
        let dispatched: Vec<_> =
            self.groups.iter().filter(|group| group.dispatch_index.is_some()).collect();
        if !dispatched.is_empty() {
            for air in 0..self.num_airs {
                writeln!(
                    out,
                    "\n    # AIR {air}: address each packed word by its proof position.\n    \
                    {position} mul.4 dup.2 add\n    # => [base, pos_ptr, table]",
                    position = scatter_position_load(air)
                )
                .expect("writing to String cannot fail");
                for (record, groups) in dispatched.chunks(2).enumerate() {
                    if let Some(second) = groups.get(1) {
                        let segment = &second.segments[air];
                        writeln!(
                            out,
                            "    dup.2 add.{digest} push.{dst}",
                            digest = self.digest_offset_for(segment.blocks),
                            dst = segment.dst,
                        )
                        .expect("writing to String cannot fail");
                    } else {
                        out.push_str("    push.0.0\n");
                    }
                    let first = &groups[0].segments[air];
                    let slot = OOD_SCATTER_SLOTS_OFFSET + WORD_FELTS * self.num_airs * record;
                    writeln!(
                        out,
                        "    dup.4 add.{digest} push.{dst}\n    \
                        # => [dst0, pipe0, dst1, pipe1, base, pos_ptr, table]\n    \
                        dup.4 add.{slot} mem_storew_le dropw",
                        digest = self.digest_offset_for(first.blocks),
                        dst = first.dst,
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
    dup.12 mem_store.OOD_SCATTER_TABLE_PTR
    # Dispatch records reuse rate slots; every nonempty pipe overwrites both rate words.
    # Word swaps expose the destination beside the record, preserving CV and Horner state.
"#,
            row_felts = self.row_felts
        )
        .expect("writing to String cannot fail");
        for group in &self.groups {
            for (position, segment) in group.segments.iter().enumerate() {
                match group.dispatch_index {
                    Some(index) => {
                        let record = index / 2 * self.num_airs + position;
                        let record_load = format!("mem_loadw_le.OOD_SCATTER_RECORD_{record}_PTR");
                        writeln!(
                            out,
                            r#"    # {group} group, proof position {position}
    {record_load}{select}
    mem_load.OOD_SCATTER_TABLE_PTR add
    swapw swapw.3 swap.4 swapw.3
    # => [scratch(5), pipe_address, scratch(2), cv(4), ptr, alpha_ptr, acc0, acc1]
    dup.5 dynexec"#,
                            group = group.name,
                            select = if index % 2 == 0 { "" } else { " movup.3 movup.3" },
                        )
                        .expect("writing to String cannot fail");
                    },
                    None => {
                        writeln!(
                            out,
                            "    # {} group, sole occupant: {} blocks at row offset {}",
                            group.name, segment.blocks, segment.dst,
                        )
                        .expect("writing to String cannot fail");
                        // Offset zero is the first nonempty segment, so the input pointer is ready.
                        if segment.dst != 0 {
                            writeln!(
                                out,
                                "    mem_load.OOD_SCATTER_TABLE_PTR add.{}\n    swap.13 drop",
                                segment.dst,
                            )
                            .expect("writing to String cannot fail");
                        }
                        writeln!(out, "    exec.pipe_{}", segment.blocks)
                            .expect("writing to String cannot fail");
                    },
                }
            }
        }
        // The nonempty quotient is last in wire and canonical order; its pipe returns the row end.
        out.push_str("end\n");
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
