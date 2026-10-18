//! Portable OOD scatter planning shared by VM and PVM verifiers.

use alloc::vec::Vec;
use core::ops::Range;

use crate::EXT_DEGREE;

const ADV_PIPE_BLOCK_FELTS: usize = 8;
const WORD_FELTS: usize = 4;
// The first word holds the active row pointer; dispatch pairs follow it.
const OOD_SCATTER_SLOTS_OFFSET: usize = 4;

/// One canonical OOD segment, measured in base-field cells and eight-cell advice blocks.
#[derive(Clone, Debug)]
pub struct OodScatterSegment {
    /// Canonical destination, in felts from the row base.
    dst: usize,
    /// Segment length in `adv_pipe` blocks.
    blocks: usize,
}

/// One commitment group in wire order, with optional proof-order dispatch slots.
#[derive(Clone, Debug)]
pub struct OodScatterGroup {
    name: &'static str,
    /// Nonempty segments in canonical row order.
    segments: Vec<OodScatterSegment>,
    /// First dispatch slot, or `None` for a group with at most one occupant.
    /// Dispatched groups have one segment per AIR and one slot per proof position.
    slot_start: Option<usize>,
}

impl OodScatterSegment {
    /// Destination in base-field cells from the canonical row base.
    pub fn destination(&self) -> usize {
        self.dst
    }

    /// Number of eight-cell advice blocks in this segment.
    pub fn blocks(&self) -> usize {
        self.blocks
    }
}

impl OodScatterGroup {
    /// Commitment group name in the canonical wire protocol.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Nonempty segments in canonical instance order.
    pub fn segments(&self) -> &[OodScatterSegment] {
        &self.segments
    }

    /// First proof-position slot, or none for empty and sole-occupant groups.
    pub fn slot_start(&self) -> Option<usize> {
        self.slot_start
    }
}

/// Canonical row destinations and proof-order dispatch slots for OOD evaluations.
pub struct OodScatterPlan {
    num_airs: usize,
    row_felts: usize,
    groups: Vec<OodScatterGroup>,
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
    /// Invalid authored geometry panics, including overflow in release builds.
    pub fn new(
        preprocessed: &[usize],
        main: &[usize],
        aux: &[usize],
        quotient_width: usize,
    ) -> Self {
        let num_airs = main.len();
        assert!(
            (num_airs != 0 && preprocessed.len() == num_airs && aux.len() == num_airs),
            "scatter groups must describe the same nonempty AIR set"
        );
        assert!(quotient_width != 0, "the quotient scatter segment must be nonempty");
        let widths = || preprocessed.iter().chain(main).chain(aux).chain([&quotient_width]);
        assert!(
            widths().all(|width| width.is_multiple_of(ADV_PIPE_BLOCK_FELTS / EXT_DEGREE)),
            "scatter segments must be 8-felt aligned"
        );
        let row_felts = widths()
            .try_fold(0usize, |total, width| total.checked_add(*width))
            .and_then(|total| total.checked_mul(EXT_DEGREE))
            .filter(|&total| u32::try_from(total).is_ok())
            .expect("the OOD row length must fit in a u32 address offset");

        let mut groups = Vec::with_capacity(4);
        let mut dst = 0;
        let mut slots = 0;
        for (name, widths) in [("preprocessed", preprocessed), ("main", main), ("aux", aux)] {
            let occupied = widths.iter().filter(|&&width| width != 0).count();
            // Proof positions rank all AIRs. A partially occupied group would need ranks
            // among its occupants to index its dispatch slots.
            assert!(
                (occupied <= 1 || occupied == num_airs),
                "the {name} commitment group is occupied by {occupied} of {num_airs} AIRs; \
                         dispatch by proof position requires every AIR to occupy the group"
            );
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
                    let segment = OodScatterSegment {
                        dst,
                        blocks: felts / ADV_PIPE_BLOCK_FELTS,
                    };
                    dst += felts;
                    segment
                })
                .collect();
            groups.push(OodScatterGroup { name, segments, slot_start });
        }
        groups.push(OodScatterGroup {
            name: "quotient",
            segments: vec![OodScatterSegment {
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
        Self { num_airs, row_felts, groups, lengths }
    }

    /// Number of canonical AIR instances.
    pub fn num_airs(&self) -> usize {
        self.num_airs
    }

    /// Number of base-field cells in one complete OOD row.
    pub fn row_felts(&self) -> usize {
        self.row_felts
    }

    /// Commitment groups in protocol wire order.
    pub fn groups(&self) -> &[OodScatterGroup] {
        &self.groups
    }

    /// Distinct advice-block lengths in ascending order.
    pub fn pipe_lengths(&self) -> &[usize] {
        &self.lengths
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
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn scatter_rejects_incomplete_or_unaddressable_rows() {
        OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 4);
        assert!(
            std::panic::catch_unwind(|| OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 2)).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| OodScatterPlan::new(&[0, 0], &[4, 4], &[4, 4], 0)).is_err()
        );
        // An incomplete segment also misaligns the next group's destination.
        assert!(
            std::panic::catch_unwind(|| OodScatterPlan::new(&[2, 0], &[4, 4], &[4, 4], 4)).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| OodScatterPlan::new(&[0], &[usize::MAX - 3], &[0], 4))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| OodScatterPlan::new(&[0], &[1 << 31], &[0], 4)).is_err()
        );
    }
}
