//! Witness generation for the byte-pair lookup table chiplet.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, utils::RowMajorMatrix};
pub use miden_precompiles_air::primitives::byte_pair_lut::*;

use crate::relations::ProvideMult;

// REQUIRES (IR)
// ================================================================================================

/// Per-relation multiplicities for a single `(a, b)` pair — one slot per
/// relation contribution, mirroring the multiplicity columns in the trace.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Multiplicities {
    pub andnot: ProvideMult,
    pub xor: ProvideMult,
    pub range16: ProvideMult,
}

impl Multiplicities {
    pub fn op(&self, op: BytePairOp) -> u32 {
        match op {
            BytePairOp::AndNot => self.andnot,
            BytePairOp::Xor => self.xor,
        }
    }

    /// True if any of the three multiplicities is non-zero. A zero
    /// `Multiplicities` corresponds to an `(a, b)` pair that no caller
    /// has touched, and contributes no trace row.
    pub fn is_nonzero(&self) -> bool {
        self.andnot != 0 || self.xor != 0 || self.range16 != 0
    }
}

/// Number of unique `(a, b)` byte pairs the LUT can hold:
/// `256 × 256 = 2^16`. `BytePairLutRequires` allocates a flat
/// multiplicity slot per pair.
const NUM_BYTE_PAIRS: usize = 1 << 16;

/// Map `(a, b)` → flat index in [0, [`NUM_BYTE_PAIRS`]). High byte is
/// `a`, low byte is `b`, so iterating in index order yields the rows
/// in lex `(a, b)` order — exactly [`generate_trace`]'s emission order.
const fn pair_idx(a: u8, b: u8) -> usize {
    ((a as usize) << 8) | (b as usize)
}

/// Accumulates the `(a, b)` pairs *required* of the byte-pair-LUT chiplet
/// across both relations it provides ([`BytePairLutMsg`] and [`Range16Msg`]).
///
/// Backed by a flat `Vec<Multiplicities>` of length `NUM_BYTE_PAIRS`,
/// indexed by `pair_idx`. Lookups and increments are O(1) array
/// accesses; [`generate_trace`] walks the backing vector in order to
/// emit one trace row per `(a, b)` lex index.
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

    /// Raise one require for the [`BytePairLutMsg`] relation on `(op, a, b)`;
    /// returns `op(a, b)` for caller convenience.
    pub fn require(&mut self, op: BytePairOp, a: u8, b: u8) -> u8 {
        let mults = &mut self.counts[pair_idx(a, b)];
        match op {
            BytePairOp::AndNot => mults.andnot += 1,
            BytePairOp::Xor => mults.xor += 1,
        }
        op.apply(a, b)
    }

    /// Raise one require for the [`Range16Msg`] relation on a 16-bit value `w`.
    /// The chiplet splits `w = a + 256·b` (LSB byte first) and bumps the
    /// `range16` multiplicity on the matching row.
    pub fn require_range16(&mut self, w: u16) {
        let a = (w & 0xff) as u8;
        let b = (w >> 8) as u8;
        self.counts[pair_idx(a, b)].range16 += 1;
    }

    pub fn multiplicity(&self, op: BytePairOp, a: u8, b: u8) -> ProvideMult {
        self.counts[pair_idx(a, b)].op(op)
    }

    pub fn multiplicity_range16(&self, w: u16) -> ProvideMult {
        let a = (w & 0xff) as u8;
        let b = (w >> 8) as u8;
        self.counts[pair_idx(a, b)].range16
    }
}

/// Verify a 64-bit `op(a, b)` byte-by-byte against 8 [`BytePairLutMsg`]
/// requires (implicitly range-checking each byte), returning the result.
/// Shared by every caller that commits 64-bit operands as bytes and needs
/// their logic result range-checked without a chain trick or an
/// intermediate chiplet — each caller commits its own `a`/`b`/result bytes
/// and drives this same 8-request pattern to pin them.
pub fn require_logic64(bpl_req: &mut BytePairLutRequires, op: BytePairOp, a: u64, b: u64) -> u64 {
    let a_bytes = a.to_le_bytes();
    let b_bytes = b.to_le_bytes();
    for i in 0..8 {
        bpl_req.require(op, a_bytes[i], b_bytes[i]);
    }
    match op {
        BytePairOp::AndNot => (!a) & b,
        BytePairOp::Xor => a ^ b,
    }
}

// TRACE GENERATION
// ================================================================================================

/// Witness main trace: the three multiplicity columns, fixed at
/// [`TRACE_HEIGHT`] = `2^16` rows — one per `(a, b) ∈ [0, 256)²` in lex
/// order (`idx = (a << 8) | b`). Row `r` lines up with row `r` of the
/// preprocessed `preprocessed_table`, so the data and multiplicities
/// share an index. Multiplicities are pulled from `requires` and are zero
/// on untouched rows.
///
/// The data columns `a`, `b`, `c_andnot`, `c_xor` are not here — they are
/// the verifier-known preprocessed table, so they cannot be forged.
pub fn generate_trace(requires: BytePairLutRequires) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(TRACE_HEIGHT * NUM_MAIN_COLS);

    for mults in &requires.counts {
        values.extend([Felt::from(mults.andnot), Felt::from(mults.xor), Felt::from(mults.range16)]);
    }

    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}
