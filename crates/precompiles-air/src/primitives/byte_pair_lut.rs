//! Byte-pair lookup table chiplet.
//!
//! Provides the PVM's canonical byte-pair and 16-bit range relations over one fixed table:
//!
//! - [`BytePairLutMsg`]: tuple `(a, b, h)` where `h = a & b`. XOR and ANDNOT consumers map their
//!   result to `h` with affine identities, so all three logic operations use one relation.
//! - [`EidosRotationMsg`]: tuple `(a, b, contribution)` on one of eight position-specific Eidos
//!   rotation buses.
//! - [`Range16Msg`]: tuple `(w,)` where `w ∈ [0, 2^16)`. Used by callers that need a 16-bit range
//!   check on a packed 16-bit Felt without spending a bytewise-op slot. The chiplet splits `w = a +
//!   256·b` (LSB byte first) and provides for the matching row.
//!
//! Fixed columns are `[a, b, h, W12(x), W7(x)]`, where `x = a xor b` and only the two wrapping
//! rotation contributions need dedicated fixed outputs. The other six contributions are affine in
//! `x`. Ten witness columns carry independent multiplicities for the canonical logic relation,
//! eight rotation relations, and Range16.
//!
//! # Soundness
//!
//! The preprocessed table enumerates every `(a, b) ∈ [0, 256)²` in lexicographic order and fixes
//! the deterministic outputs. It is verifier-known, so a prover can only choose relation
//! multiplicities. Global lookup balance determines those multiplicities from consumers.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        Challenges, ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES,
        NUM_RANDOMNESS, build_logup_aux_trace, frac_col,
    },
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS, eidos_rot7_bus, eidos_rot12_bus},
    utils::current_main,
};

// OPERATION
// ================================================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BytePairOp {
    And,
    /// `(NOT a) AND b` — Keccak χ convention.
    AndNot,
    Xor,
}

impl BytePairOp {
    pub fn apply(self, a: u8, b: u8) -> u8 {
        match self {
            BytePairOp::And => a & b,
            BytePairOp::AndNot => (!a) & b,
            BytePairOp::Xor => a ^ b,
        }
    }

    /// Applies the same bytewise operation to a 64-bit word.
    pub fn apply_u64(self, a: u64, b: u64) -> u64 {
        match self {
            BytePairOp::And => a & b,
            BytePairOp::AndNot => (!a) & b,
            BytePairOp::Xor => a ^ b,
        }
    }
}

/// Eidos rotation family served by the canonical byte-pair table.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum EidosRotation {
    Rot12,
    Rot7,
}

/// Contribution of one XOR byte to the selected 32-bit Eidos rotation.
#[doc(hidden)]
pub const fn eidos_rotation_contribution(
    rotation: EidosRotation,
    byte: usize,
    a: u8,
    b: u8,
) -> u32 {
    assert!(byte < 4, "Eidos byte position must be in 0..4");
    let word = ((a ^ b) as u32) << (8 * byte);
    match rotation {
        EidosRotation::Rot12 => word.rotate_right(12),
        EidosRotation::Rot7 => word.rotate_right(7),
    }
}

// COLUMN LAYOUT
// ================================================================================================
//
// Witness `main` carries only multiplicities. Deterministic byte values and results live in the
// verifier-known preprocessed table.

pub const COL_MULT_LOGIC: usize = 0;
pub const COL_MULT_ROT12_BEGIN: usize = COL_MULT_LOGIC + 1;
pub const COL_MULT_ROT7_BEGIN: usize = COL_MULT_ROT12_BEGIN + 4;
pub const COL_MULT_RANGE16: usize = COL_MULT_ROT7_BEGIN + 4;
pub const NUM_MAIN_COLS: usize = COL_MULT_RANGE16 + 1;
pub const NUM_AUX_COLS: usize = 5;
/// Width of the preprocessed table `[a, b, h, W12(x), W7(x)]`.
pub const NUM_PREPROCESSED_COLS: usize = 5;

/// Column indices into the preprocessed data table (see [`preprocessed_table`]).
pub const PRE_A: usize = 0;
pub const PRE_B: usize = 1;
pub const PRE_AND: usize = 2;
pub const PRE_WRAP12: usize = 3;
pub const PRE_WRAP7: usize = 4;

/// Multiplicative inverse of two in the Miden base field.
const FELT_INV_TWO: Felt = Felt::new_unchecked(9_223_372_034_707_292_161);

/// Recover `(!a) & b` from `x = a xor b` using `(x - a + b) / 2`.
///
/// The identity is linear, so it also holds when byte tuples are packed with common positional
/// weights, as in Keccak's 32-bit Memory64 limbs.
pub(crate) fn andnot_result_from_xor<E: Algebra<Felt>>(a: E, b: E, x: E) -> E {
    (x - a + b) * FELT_INV_TWO
}

/// Fixed trace height: every `(a, b) ∈ [0, 256)²` gets a row, in lex
/// order (`idx = (a << 8) | b`). The preprocessed data table
/// (`preprocessed_table`) is pinned to this lex enumeration on these
/// `2^16` rows; the ten witness multiplicity columns are committed in
/// lockstep at the same height.
pub const TRACE_HEIGHT: usize = 1 << 16;
const NUM_BYTE_PAIRS: usize = TRACE_HEIGHT;

// PREPROCESSED TABLE
// ================================================================================================

/// Fixed `[a, b, h, W12(x), W7(x)]` table, where `h = a & b` and `x = a xor b`.
pub fn preprocessed_table() -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(TRACE_HEIGHT * NUM_PREPROCESSED_COLS);
    for idx in 0..NUM_BYTE_PAIRS {
        let a = (idx >> 8) as u8;
        let b = (idx & 0xff) as u8;
        let h = a & b;
        values.extend([
            Felt::from(a),
            Felt::from(b),
            Felt::from(h),
            Felt::from(eidos_rotation_contribution(EidosRotation::Rot12, 1, a, b)),
            Felt::from(eidos_rotation_contribution(EidosRotation::Rot7, 0, a, b)),
        ]);
    }
    RowMajorMatrix::new(values, NUM_PREPROCESSED_COLS)
}

// MESSAGES
// ================================================================================================

/// Canonical byte-pair message `(a, b, h)`, where `h = a & b`.
#[derive(Debug, Clone)]
pub struct BytePairLutMsg<E> {
    a: E,
    b: E,
    h: E,
}

impl<E> BytePairLutMsg<E>
where
    E: Algebra<Felt>,
{
    /// Construct from an ordinary AND result.
    pub fn from_and(a: E, b: E, h: E) -> Self {
        Self { a, b, h }
    }

    /// Construct from `x = a xor b` using `h = (a + b - x) / 2`.
    pub fn from_xor(a: E, b: E, x: E) -> Self {
        let h = (a.clone() + b.clone() - x) * FELT_INV_TWO;
        Self { a, b, h }
    }

    /// Construct from `c = (!a) & b` using `h = b - c`.
    pub fn from_andnot(a: E, b: E, c: E) -> Self {
        let h = b.clone() - c;
        Self { a, b, h }
    }
}

impl<E, EF> LookupMessage<E, EF> for BytePairLutMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges
            .encode(BusId::BytePairLut as usize, [self.a.clone(), self.b.clone(), self.h.clone()])
    }
}

/// Position-specific Eidos rotation contribution over a byte pair.
#[derive(Debug, Clone)]
pub(crate) struct EidosRotationMsg<E> {
    bus: BusId,
    a: E,
    b: E,
    result: E,
}

impl<E> EidosRotationMsg<E> {
    fn new(rotation: EidosRotation, byte: usize, a: E, b: E, result: E) -> Self {
        let bus = match rotation {
            EidosRotation::Rot12 => eidos_rot12_bus(byte),
            EidosRotation::Rot7 => eidos_rot7_bus(byte),
        };
        Self { bus, a, b, result }
    }
}

impl<E, EF> LookupMessage<E, EF> for EidosRotationMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(self.bus as usize, [self.a.clone(), self.b.clone(), self.result.clone()])
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
        Some(preprocessed_table())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_COLS
    }

    fn num_public_values(&self) -> usize {
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
        NUM_LOGUP_VALUES
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
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

// LOOKUP AIR
// ================================================================================================

/// Ten linear provider relations, paired into five degree-three LogUp columns.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2; NUM_AUX_COLS];

impl<LB> LookupAir<LB> for BytePairLutAir
where
    LB: LookupBuilder<F = Felt>,
{
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
        let preprocessed: [LB::Var; NUM_PREPROCESSED_COLS] =
            current_main(builder.preprocessed().clone(), 0);
        let main: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);

        let a_value: LB::Expr = preprocessed[PRE_A].into();
        let b_value: LB::Expr = preprocessed[PRE_B].into();
        let h: LB::Expr = preprocessed[PRE_AND].into();
        let wrap12: LB::Expr = preprocessed[PRE_WRAP12].into();
        let wrap7: LB::Expr = preprocessed[PRE_WRAP7].into();
        let x = a_value.clone() + b_value.clone() - LB::Expr::from_u8(2) * h.clone();
        let rot12 = [
            LB::Expr::from_u64(1 << 20) * x.clone(),
            wrap12,
            LB::Expr::from_u8(16) * x.clone(),
            LB::Expr::from_u64(1 << 12) * x.clone(),
        ];
        let rot7 = [
            wrap7,
            LB::Expr::from_u8(2) * x.clone(),
            LB::Expr::from_u64(1 << 9) * x.clone(),
            LB::Expr::from_u64(1 << 17) * x,
        ];
        let w = a_value.clone() + LB::Expr::from_u16(256) * b_value.clone();

        let neg_logic = LB::Expr::ZERO - LB::Expr::from(main[COL_MULT_LOGIC]);
        let neg_rot12: [LB::Expr; 4] = core::array::from_fn(|byte| {
            LB::Expr::ZERO - LB::Expr::from(main[COL_MULT_ROT12_BEGIN + byte])
        });
        let neg_rot7: [LB::Expr; 4] = core::array::from_fn(|byte| {
            LB::Expr::ZERO - LB::Expr::from(main[COL_MULT_ROT7_BEGIN + byte])
        });
        let neg_range16 = LB::Expr::ZERO - LB::Expr::from(main[COL_MULT_RANGE16]);

        let interaction_deg = Deg { v: 1, u: 1 };
        let pair_deg = Deg { v: 2, u: 2 };

        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "logic",
                neg_logic,
                BytePairLutMsg::from_and(a_value.clone(), b_value.clone(), h),
                interaction_deg
            ),
            (
                "rot12-pos0",
                neg_rot12[0].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot12,
                    0,
                    a_value.clone(),
                    b_value.clone(),
                    rot12[0].clone(),
                ),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot12-pos1",
                neg_rot12[1].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot12,
                    1,
                    a_value.clone(),
                    b_value.clone(),
                    rot12[1].clone(),
                ),
                interaction_deg
            ),
            (
                "rot12-pos2",
                neg_rot12[2].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot12,
                    2,
                    a_value.clone(),
                    b_value.clone(),
                    rot12[2].clone(),
                ),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot12-pos3",
                neg_rot12[3].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot12,
                    3,
                    a_value.clone(),
                    b_value.clone(),
                    rot12[3].clone(),
                ),
                interaction_deg
            ),
            (
                "rot7-pos0",
                neg_rot7[0].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot7,
                    0,
                    a_value.clone(),
                    b_value.clone(),
                    rot7[0].clone(),
                ),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot7-pos1",
                neg_rot7[1].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot7,
                    1,
                    a_value.clone(),
                    b_value.clone(),
                    rot7[1].clone(),
                ),
                interaction_deg
            ),
            (
                "rot7-pos2",
                neg_rot7[2].clone(),
                EidosRotationMsg::new(
                    EidosRotation::Rot7,
                    2,
                    a_value.clone(),
                    b_value.clone(),
                    rot7[2].clone(),
                ),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot7-pos3",
                neg_rot7[3].clone(),
                EidosRotationMsg::new(EidosRotation::Rot7, 3, a_value, b_value, rot7[3].clone(),),
                interaction_deg
            ),
            ("range16", neg_range16, Range16Msg { w }, interaction_deg),
        );
    }
}

// PROVER
// ================================================================================================

/// Builds the chiplet's auxiliary trace from witness multiplicities. The shared driver obtains the
/// fixed table through [`BaseAir::preprocessed_trace`], matching the constraint-side
/// `LookupBuilder::preprocessed` window.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&BytePairLutAir, main, challenges)
}
