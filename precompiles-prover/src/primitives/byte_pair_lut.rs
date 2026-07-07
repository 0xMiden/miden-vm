//! Byte-pair lookup table chiplet.
//!
//! Provides two relations over the same trace rows:
//!
//! - [`BytePairLutMsg`]: tuple `(op, a, b, c)` where `op ∈ {AndNot, Xor}`, `a, b ∈ [0, 256)`, and
//!   `c = op.apply(a, b)`. Used by callers that need a byte-level bitwise op result, with the
//!   inputs implicitly range-checked to bytes.
//! - [`Range16Msg`]: tuple `(w,)` where `w ∈ [0, 2^16)`. Used by callers that need a 16-bit range
//!   check on a packed 16-bit Felt without spending a bytewise-op slot. The chiplet splits `w = a +
//!   256·b` (LSB byte first) and provides for the matching row.
//!
//! The data `a`, `b` and the precomputed bytewise results `c_andnot`,
//! `c_xor` are **preprocessed** (verifier-known) columns; only three
//! multiplicity columns (one per relation contribution: AndNot, Xor,
//! Range16) are witness. All three contributions are accumulated into the
//! chiplet's single LogUp aux column. The lookup eval reads the data and
//! multiplicities together through a combined `[preprocessed ++ main]`
//! window (`logup::CombinedWindow`).
//!
//! See [`logup`](crate::logup) and `docs/lookup-argument.md` for the
//! lookup-argument architecture.
//!
//! # Soundness
//!
//! The data columns `a`, `b`, `c_andnot`, `c_xor` are the fixed,
//! verifier-known `preprocessed_table` — committed once, enumerating
//! every `(a, b) ∈ [0, 256)²` in lex order with the correct bytewise
//! results. They are not witness, so a prover cannot forge them:
//! `a, b ∈ [0, 256)` and `c_andnot = (!a) & b`, `c_xor = a ^ b` hold by
//! construction. The LogUp `(op, a, b, c)` / `(w,)` tuples the chiplet
//! provides are therefore pinned to correct values, and callers of
//! [`BytePairLutMsg`] / [`Range16Msg`] inherit sound range checks and
//! bitwise-op results. Only the three multiplicity columns are witness
//! (range-unchecked under the fixed-consume invariant — see
//! `docs/lookup-argument.md`).

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES, build_logup_aux_trace, frac_col,
    },
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS, ProvideMult},
    utils::current_main,
};

// OPERATION
// ================================================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BytePairOp {
    /// `(NOT a) AND b` — Keccak χ convention.
    AndNot,
    Xor,
}

impl BytePairOp {
    pub fn apply(self, a: u8, b: u8) -> u8 {
        match self {
            BytePairOp::AndNot => (!a) & b,
            BytePairOp::Xor => a ^ b,
        }
    }

    /// Numeric tag used in the [`BytePairLutMsg`] relation tuple's `op` slot.
    pub fn tag(self) -> u8 {
        match self {
            BytePairOp::AndNot => 0,
            BytePairOp::Xor => 1,
        }
    }
}

// COLUMN LAYOUT
// ================================================================================================
//
// Witness `main` carries only the three multiplicity columns. The data
// columns `a`, `b`, `c_andnot`, `c_xor` are **preprocessed** — the fixed,
// verifier-known [`preprocessed_table`] — so they are not witness and
// cannot be forged. The lookup eval reads them via the combined
// `[preprocessed ++ main]` window (see `logup::CombinedWindow`), where the
// preprocessed columns come first (`PRE_*`) and the multiplicities follow
// at `NUM_PREPROCESSED_COLS + COL_MULT_*`.

pub const COL_MULT_ANDNOT: usize = 0;
pub const COL_MULT_XOR: usize = 1;
pub const COL_MULT_RANGE16: usize = 2;
pub const NUM_MAIN_COLS: usize = 3;
pub const NUM_AUX_COLS: usize = 2;
/// Width of the preprocessed (verifier-known) data table: `a`, `b`,
/// `c_andnot`, `c_xor`. See `preprocessed_table`.
pub const NUM_PREPROCESSED_COLS: usize = 4;

/// Column indices into the preprocessed data table (see
/// `preprocessed_table`). These are also the lookup eval's indices into
/// the combined `[preprocessed ++ main]` window, which places the
/// preprocessed columns first.
pub const PRE_A: usize = 0;
pub const PRE_B: usize = 1;
pub const PRE_C_ANDNOT: usize = 2;
pub const PRE_C_XOR: usize = 3;

/// Width of the combined `[preprocessed ++ main]` window the lookup eval
/// reads: the 4 preprocessed data columns followed by the 3 witness
/// multiplicities. `PRE_*` index the data; `NUM_PREPROCESSED_COLS +
/// COL_MULT_*` index the multiplicities.
pub const NUM_LOOKUP_COLS: usize = NUM_PREPROCESSED_COLS + NUM_MAIN_COLS;
// The single exposed σ ([`NUM_SIGMA_VALUES`]) and the shared
// transcript-root public values ([`NUM_PUBLIC_VALUES`]) follow the
// VM-wide LogUp contract in [`crate::logup`]; the natural last-row
// σ-closing needs no `inv_n`, and this chiplet declares the root but
// does not read it.

/// Fixed trace height: every `(a, b) ∈ [0, 256)²` gets a row, in lex
/// order (`idx = (a << 8) | b`). The preprocessed data table
/// (`preprocessed_table`) is pinned to this lex enumeration on these
/// `2^16` rows; the three witness multiplicity columns are committed in
/// lockstep at the same height.
pub const TRACE_HEIGHT: usize = 1 << 16;

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

// PREPROCESSED TABLE
// ================================================================================================

/// The fixed `2^16 × 4` data table committed once as preprocessed
/// (verifier-known) columns: every `(a, b) ∈ [0, 256)²` in lex order
/// (`idx = (a << 8) | b`) with `c_andnot = (!a) & b` and `c_xor = a ^ b`.
///
/// Column order matches [`PRE_A`], [`PRE_B`], [`PRE_C_ANDNOT`],
/// [`PRE_C_XOR`]. Because the table is fixed and verifier-committed, the
/// LogUp `(op, a, b, c)` / `(w,)` tuples it provides are pinned to the
/// correct bytewise-op results — this is what makes the chiplet sound.
pub(crate) fn preprocessed_table() -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(TRACE_HEIGHT * NUM_PREPROCESSED_COLS);
    for idx in 0..NUM_BYTE_PAIRS {
        let a = (idx >> 8) as u8;
        let b = (idx & 0xff) as u8;
        values.extend([
            Felt::from(a),
            Felt::from(b),
            Felt::from(BytePairOp::AndNot.apply(a, b)),
            Felt::from(BytePairOp::Xor.apply(a, b)),
        ]);
    }
    RowMajorMatrix::new(values, NUM_PREPROCESSED_COLS)
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

// MESSAGES
// ================================================================================================

/// LogUp message for the `BytePairLut` relation: a 4-tuple `(op, a, b, c)`
/// describing an 8-bit bitwise operation result.
///
/// - `op ∈ {0 = AndNot, 1 = Xor}` — operation tag (see [`BytePairOp::tag`])
/// - `a, b ∈ [0, 256)` — 8-bit operands
/// - `c = op.apply(a, b)` — 8-bit result
///
/// Provided by [`BytePairLutAir`] on bus [`BusId::BytePairLut`]. Encoded
/// as `bus_prefix[BytePairLut] + β⁰·op + β¹·a + β²·b + β³·c`.
///
/// Any successful `BytePairLut` lookup constrains `a, b ∈ [0, 256)`, so
/// it implicitly range-checks the byte pair. For callers that want a
/// 16-bit RC without picking a specific bytewise op, [`Range16Msg`] is
/// the more direct interface.
#[derive(Debug, Clone)]
pub struct BytePairLutMsg<E> {
    pub op: E,
    pub a: E,
    pub b: E,
    pub c: E,
}

impl<E, EF> LookupMessage<E, EF> for BytePairLutMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::BytePairLut as usize,
            [self.op.clone(), self.a.clone(), self.b.clone(), self.c.clone()],
        )
    }
}

/// LogUp message for the `Range16` relation: a 1-tuple `(w,)` where
/// `w ∈ [0, 2^16)`.
///
/// Provided by [`BytePairLutAir`] on bus [`BusId::Range16`]. Each
/// chiplet row provides the relation for `w = a + 256·b` (LSB byte
/// first), so callers carrying a single packed 16-bit Felt can
/// range-check it directly without splitting it into bytes themselves
/// and without consuming a bytewise-op slot. Encoded as
/// `bus_prefix[Range16] + β⁰·w`.
#[derive(Debug, Clone)]
pub struct Range16Msg<E> {
    pub w: E,
}

impl<E, EF> LookupMessage<E, EF> for Range16Msg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(BusId::Range16 as usize, [self.w.clone()])
    }
}

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct BytePairLutAir;

impl BaseAir<Felt> for BytePairLutAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        // The fixed `(a, b, c_andnot, c_xor)` table — verifier-known,
        // committed once. Its `2^16` height matches the main trace.
        Some(preprocessed_table())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_COLS
    }

    fn num_public_values(&self) -> usize {
        // The shared 4-felt transcript root (declared, unread by BPL);
        // the natural last-row σ-closing needs no `inv_n`.
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for BytePairLutAir {
    fn num_randomness(&self) -> usize {
        // Single global (α, β) pair shared across all relations; each
        // relation's bus_prefix keeps encodings unambiguous.
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        // The chiplet's LogUp residue σ = Σ delta_r, exposed for
        // cross-AIR identity. Col 0 is the plain running sum (no
        // correction per step); σ is committed separately as the
        // permutation value at `permutation_values()[0]`, and the
        // natural last-row σ-closing pins it to Σ delta_r.
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: no non-LogUp constraints. The data columns `a`, `b`,
        // `c_andnot`, `c_xor` are preprocessed (verifier-known), so they
        // need no binding constraints — they cannot be forged.
        //
        // Phase 2: LogUp argument via the LogUp adapter. Wraps `builder`
        // in our [`CyclicConstraintLookupBuilder`] and dispatches to the
        // [`LookupAir`] impl below. The adapter's `main()` presents the
        // combined `[preprocessed ++ main]` window the eval reads.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Per-column emission shape: column 0 is the gated running-sum anchor
/// (the AndNot self-provide alone); column 1 pairs the Xor and Range16
/// self-provides, keeping each closing constraint at degree ≤ 3.
const COLUMN_SHAPE: [usize; 2] = [1, 2];

impl<LB> LookupAir<LB> for BytePairLutAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        // The combined `[preprocessed ++ main]` window: `PRE_*` index the
        // verifier-known data columns, `NUM_PREPROCESSED_COLS + COL_MULT_*`
        // the witness multiplicities.
        let local: [LB::Var; NUM_LOOKUP_COLS] = current_main(builder.main(), 0);

        let a_value: LB::Expr = local[PRE_A].into();
        let b_value: LB::Expr = local[PRE_B].into();
        let c_andnot: LB::Expr = local[PRE_C_ANDNOT].into();
        let c_xor: LB::Expr = local[PRE_C_XOR].into();
        let andnot_op: LB::Expr = LB::Expr::from(Felt::from(BytePairOp::AndNot.tag()));
        let xor_op: LB::Expr = LB::Expr::from(Felt::from(BytePairOp::Xor.tag()));
        let two_56: LB::Expr = LB::Expr::from(Felt::from(256u16));
        let w: LB::Expr = a_value.clone() + two_56 * b_value.clone();

        let mult_andnot: LB::Expr = local[NUM_PREPROCESSED_COLS + COL_MULT_ANDNOT].into();
        let mult_xor: LB::Expr = local[NUM_PREPROCESSED_COLS + COL_MULT_XOR].into();
        let mult_range16: LB::Expr = local[NUM_PREPROCESSED_COLS + COL_MULT_RANGE16].into();
        // Provides ⇒ negative multiplicity contribution.
        let neg_andnot: LB::Expr = LB::Expr::ZERO - mult_andnot;
        let neg_xor: LB::Expr = LB::Expr::ZERO - mult_xor;
        let neg_range16: LB::Expr = LB::Expr::ZERO - mult_range16;

        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: AndNot self-provide alone — the gated running-sum anchor.
        frac_col!(
            builder,
            "bpl-self-provides",
            provides_deg,
            (
                "andnot",
                neg_andnot,
                BytePairLutMsg {
                    op: andnot_op,
                    a: a_value.clone(),
                    b: b_value.clone(),
                    c: c_andnot,
                },
                interaction_deg
            ),
        );
        // col 1 (paired, lqd-1): the Xor and Range16 self-provides.
        frac_col!(
            builder,
            "bpl-self-provides",
            pair_deg,
            (
                "xor",
                neg_xor,
                BytePairLutMsg {
                    op: xor_op,
                    a: a_value.clone(),
                    b: b_value.clone(),
                    c: c_xor,
                },
                interaction_deg
            ),
            ("range16", neg_range16, Range16Msg { w }, interaction_deg),
        );
    }
}

// PROVER
// ================================================================================================

/// Builds the chiplet's aux trace from the witness (multiplicity) main
/// trace.
///
/// The lookup fractions reference the preprocessed `(a, b, c)` data, which
/// the constraint side reads through the combined `[preprocessed ++ main]`
/// window (`logup::CombinedWindow`). The prover reproduces that combined
/// view here — reconstruct the fixed [`preprocessed_table`], prepend its
/// columns to the witness multiplicities, and drive the generic
/// [`build_logup_aux_trace`] over the combined matrix, whose column order
/// matches the eval's `PRE_*` / `NUM_PREPROCESSED_COLS + COL_MULT_*`
/// indices.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    let combined = combine_with_preprocessed(main);
    build_logup_aux_trace(&BytePairLutAir, &combined, challenges)
}

/// Row-wise `[preprocessed ++ main]`: the fixed [`preprocessed_table`]
/// columns followed by the witness multiplicity columns. Mirrors the
/// constraint-side `logup::CombinedWindow` so prover and verifier read
/// identical column indices.
fn combine_with_preprocessed(main: &RowMajorMatrix<Felt>) -> RowMajorMatrix<Felt> {
    let pre = preprocessed_table();
    let height = main.values.len() / NUM_MAIN_COLS;
    debug_assert_eq!(
        pre.values.len() / NUM_PREPROCESSED_COLS,
        height,
        "preprocessed and main trace heights must match",
    );
    let mut values = Vec::with_capacity(height * NUM_LOOKUP_COLS);
    for r in 0..height {
        let pre_row = &pre.values[r * NUM_PREPROCESSED_COLS..(r + 1) * NUM_PREPROCESSED_COLS];
        let main_row = &main.values[r * NUM_MAIN_COLS..(r + 1) * NUM_MAIN_COLS];
        values.extend_from_slice(pre_row);
        values.extend_from_slice(main_row);
    }
    RowMajorMatrix::new(values, NUM_LOOKUP_COLS)
}
