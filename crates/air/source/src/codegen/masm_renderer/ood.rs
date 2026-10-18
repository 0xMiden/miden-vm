//! OOD presentation planning over the generic ACE scatter-layout authority.

use std::vec::Vec;

use miden_ace::OodScatterPlan;

use super::proof_order::ProofOrderPlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    pub base: u32,
    pub len_felts: u32,
}

impl MemoryRegion {
    pub(crate) fn end(self) -> u64 {
        let end = u64::from(self.base) + u64::from(self.len_felts);
        assert!(
            end <= u64::from(u32::MAX) + 1,
            "memory region: region exceeds the address space"
        );
        end
    }

    pub(crate) fn overlaps(self, other: Self) -> bool {
        u64::from(self.base) < other.end() && u64::from(other.base) < self.end()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PipeHelper {
    pub blocks: u32,
    pub digest_offset: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct DispatchEntry {
    pub destination: u32,
    pub pair_offset: u32,
    pub digest_pointer_offset: u32,
    pub digest_offset: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct AirDispatch {
    pub id: usize,
    pub entries: Vec<DispatchEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DispatchCall {
    pub pair_offset: u32,
    pub digest_pointer_offset: u32,
}

#[derive(Clone, Debug)]
pub(crate) enum RowGroup {
    Sole { destination: u32, blocks: u32 },
    Full { calls: Vec<DispatchCall> },
}

#[derive(Clone, Debug)]
pub(crate) struct OodPlan {
    pub row_felts: u32,
    pub helpers: Vec<PipeHelper>,
    pub air_dispatch: Vec<AirDispatch>,
    pub row_groups: Vec<RowGroup>,
    pub proof_order: ProofOrderPlan,
}

impl OodPlan {
    pub fn new(
        scatter: &OodScatterPlan,
        scratch: MemoryRegion,
        positions: MemoryRegion,
        ids: MemoryRegion,
        proof_order: ProofOrderPlan,
    ) -> Self {
        let num_airs = scatter.num_airs();
        assert!(
            num_airs == proof_order.num_airs,
            "OOD: proof-order and scatter AIR counts differ"
        );
        let row_felts = as_u32(scatter.row_felts(), "row length");
        let required_table = as_u32(scatter.table_felts(), "table length");
        assert!(
            scratch.base.is_multiple_of(4) && scratch.len_felts >= required_table,
            "OOD: scatter scratch must be aligned and large enough"
        );
        let num_airs_u32 = as_u32(num_airs, "AIR count");
        assert!(
            positions.len_felts >= num_airs_u32 && ids.len_felts >= num_airs_u32,
            "OOD: proof-order maps are too short"
        );
        assert!(
            !scratch.overlaps(positions) && !scratch.overlaps(ids) && !positions.overlaps(ids),
            "OOD: scatter scratch and proof-order maps overlap"
        );
        let digest_start = scatter.pipe_digests().start;
        let mut helpers = Vec::new();
        for (index, &blocks) in scatter.pipe_lengths().iter().enumerate() {
            assert!(blocks != 0, "OOD: zero-length pipe helper");
            let offset = index
                .checked_mul(4)
                .and_then(|n| digest_start.checked_add(n))
                .expect("OOD: pipe digest address overflow");
            helpers.push(PipeHelper {
                blocks: as_u32(blocks, "pipe length"),
                digest_offset: as_u32(offset, "digest offset"),
            });
        }
        assert!(
            helpers.windows(2).all(|w| w[0].blocks < w[1].blocks),
            "OOD: pipe lengths must be distinct and ascending"
        );
        let mut air_dispatch: Vec<AirDispatch> =
            (0..num_airs).map(|id| AirDispatch { id, entries: Vec::new() }).collect();
        let mut row_groups = Vec::new();
        for group in scatter.groups() {
            let segments = group.segments();
            match segments.len() {
                0 => (),
                1 => {
                    row_groups.push(RowGroup::Sole {
                        destination: as_u32(segments[0].destination(), "sole destination"),
                        blocks: as_u32(segments[0].blocks(), "sole pipe length"),
                    });
                },
                count if count == num_airs => {
                    let slot_start =
                        group.slot_start().expect("OOD: full group has no dispatch slots");
                    let pair_offset = slot_start
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(4))
                        .expect("OOD: dispatch pair offset overflow");
                    let pair_offset = as_u32(pair_offset, "dispatch pair offset");
                    for (id, segment) in segments.iter().enumerate() {
                        let blocks = as_u32(segment.blocks(), "dispatch pipe length");
                        let helper = helpers
                            .iter()
                            .find(|h| h.blocks == blocks)
                            .expect("OOD: missing pipe helper");
                        air_dispatch[id].entries.push(DispatchEntry {
                            destination: as_u32(segment.destination(), "canonical destination"),
                            pair_offset,
                            digest_pointer_offset: pair_offset
                                .checked_add(1)
                                .expect("OOD: digest pointer offset overflow"),
                            digest_offset: helper.digest_offset,
                        });
                    }
                    let mut calls = Vec::new();
                    for position in 0..num_airs {
                        let offset = as_u32(
                            position.checked_mul(2).expect("OOD: proof position overflow"),
                            "proof position",
                        );
                        let pair = pair_offset
                            .checked_add(offset)
                            .expect("OOD: dispatch pair offset overflow");
                        let digest_pointer_offset =
                            pair.checked_add(1).expect("OOD: digest pointer offset overflow");
                        calls.push(DispatchCall { pair_offset: pair, digest_pointer_offset });
                    }
                    row_groups.push(RowGroup::Full { calls });
                },
                _ => {
                    panic!("OOD: multiple partially occupied entries are unsupported");
                },
            }
        }
        Self {
            row_felts,
            helpers,
            air_dispatch,
            row_groups,
            proof_order,
        }
    }
}

pub(crate) fn as_u32(value: usize, what: &'static str) -> u32 {
    u32::try_from(value).unwrap_or_else(|_| panic!("OOD: {what} exceeds u32"))
}
