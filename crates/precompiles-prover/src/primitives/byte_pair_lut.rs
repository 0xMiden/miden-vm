//! Witness generation for the byte-pair lookup table chiplet.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, utils::RowMajorMatrix};
pub use miden_precompiles_air::primitives::byte_pair_lut::*;

use crate::relations::ProvideMult;

// REQUIRES (IR)
// ================================================================================================

/// Per-relation multiplicities for one `(a, b)` pair, mirroring the main trace.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Multiplicities {
    logic: ProvideMult,
    rot12: [ProvideMult; 4],
    rot7: [ProvideMult; 4],
    range16: ProvideMult,
}

/// Number of unique byte pairs in the fixed table.
const NUM_BYTE_PAIRS: usize = 1 << 16;

/// Maps `(a, b)` to its lexicographic table row.
const fn pair_idx(a: u8, b: u8) -> usize {
    ((a as usize) << 8) | (b as usize)
}

/// Accumulates the relations required from the canonical byte-pair table.
#[derive(Debug, Clone)]
pub struct BytePairLutRequires {
    counts: Vec<Multiplicities>,
}

impl Default for BytePairLutRequires {
    fn default() -> Self {
        Self {
            counts: vec![Multiplicities::default(); NUM_BYTE_PAIRS],
        }
    }
}

impl BytePairLutRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires a bytewise logic result.
    ///
    /// AND, ANDNOT, and XOR consume the same canonical `(a, b, a & b)` relation, so their
    /// multiplicities intentionally aggregate.
    pub fn require(&mut self, op: BytePairOp, a: u8, b: u8) -> u8 {
        self.counts[pair_idx(a, b)].logic += 1;
        op.apply(a, b)
    }

    /// Requires one byte-position contribution to an Eidos rotation.
    pub(crate) fn require_eidos_rotation(
        &mut self,
        rotation: EidosRotation,
        byte: usize,
        a: u8,
        b: u8,
    ) -> u32 {
        assert!(byte < 4, "Eidos byte position must be in 0..4");
        let multiplicities = &mut self.counts[pair_idx(a, b)];
        match rotation {
            EidosRotation::Rot12 => multiplicities.rot12[byte] += 1,
            EidosRotation::Rot7 => multiplicities.rot7[byte] += 1,
        }
        eidos_rotation_contribution(rotation, byte, a, b)
    }

    /// Requires the [`Range16Msg`] relation for `w`.
    pub fn require_range16(&mut self, w: u16) {
        let a = (w & 0xff) as u8;
        let b = (w >> 8) as u8;
        self.counts[pair_idx(a, b)].range16 += 1;
    }

    pub fn multiplicity_logic(&self, a: u8, b: u8) -> ProvideMult {
        self.counts[pair_idx(a, b)].logic
    }

    pub(crate) fn multiplicity_rotation(
        &self,
        rotation: EidosRotation,
        byte: usize,
        a: u8,
        b: u8,
    ) -> ProvideMult {
        assert!(byte < 4, "Eidos byte position must be in 0..4");
        match rotation {
            EidosRotation::Rot12 => self.counts[pair_idx(a, b)].rot12[byte],
            EidosRotation::Rot7 => self.counts[pair_idx(a, b)].rot7[byte],
        }
    }

    pub fn multiplicity_range16(&self, w: u16) -> ProvideMult {
        let a = (w & 0xff) as u8;
        let b = (w >> 8) as u8;
        self.counts[pair_idx(a, b)].range16
    }
}

/// Verifies a 64-bit logic operation byte by byte and returns its result.
pub fn require_logic64(bpl_req: &mut BytePairLutRequires, op: BytePairOp, a: u64, b: u64) -> u64 {
    let a_bytes = a.to_le_bytes();
    let b_bytes = b.to_le_bytes();
    for i in 0..8 {
        bpl_req.require(op, a_bytes[i], b_bytes[i]);
    }
    op.apply_u64(a, b)
}

// TRACE GENERATION
// ================================================================================================

/// Builds the fixed-height witness multiplicity trace in byte-pair order.
pub fn generate_trace(requires: BytePairLutRequires) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(TRACE_HEIGHT * NUM_MAIN_COLS);

    for multiplicities in &requires.counts {
        values.push(Felt::from(multiplicities.logic));
        values.extend(multiplicities.rot12.map(Felt::from));
        values.extend(multiplicities.rot7.map(Felt::from));
        values.push(Felt::from(multiplicities.range16));
    }

    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}
