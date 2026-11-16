//! Byte-pair lookup table chiplet.
//!
//! Provides the PVM's canonical byte-pair and 16-bit range relations over one fixed table:
//!
//! - [`BytePairLutMsg`]: tuple `(a, b, x)` where `x = a xor b`. AND and ANDNOT consumers map their
//!   result to `x` with affine identities, so all three logic operations use one relation.
//! - five normalized Eidos rotation relations. Three non-wrapping positions reuse the canonical XOR
//!   relation; the other positions use a row-family-independent normalization.
//! - [`Range16Msg`]: tuple `(w,)` where `w ∈ [0, 2^16)`. Used by callers that need a 16-bit range
//!   check on a packed 16-bit Felt without spending a bytewise-op slot. The chiplet splits `w = a +
//!   256·b` (LSB byte first) and provides for the matching row.
//!
//! Fixed columns are `[a, b, x, W12(x), W7(x)]`, where `x = a xor b` and only the two wrapping
//! rotation contributions need dedicated fixed outputs. The other six contributions are affine in
//! `x`. Seven witness columns carry multiplicities for the canonical XOR relation, five normalized
//! rotation relations, and Range16.
//!
//! `W12(x) = floor(x / 16) + 2^28 * (x mod 16)` and
//! `W7(x) = floor(x / 128) + 2^25 * (x mod 128)`. For byte positions zero through three, lookup
//! messages divide the physical contribution by `(2^20, 2, 2^4, 1)`, respectively.
//!
//! # Soundness
//!
//! The preprocessed table enumerates every `(a, b) ∈ [0, 256)²` in lexicographic order and fixes
//! the deterministic outputs. It is verifier-known, so a prover can only choose relation
//! multiplicities. Global lookup balance determines those multiplicities from consumers.

#[doc(hidden)]
pub mod eidos;

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air,
    lookup::{self, Challenges, Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage},
};
use p3_field::Dup;

use self::eidos::{Relation as EidosRelation, Rotation as EidosRotation};
use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
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

// COLUMN LAYOUT
// ================================================================================================
//
// Witness `main` carries only multiplicities. Deterministic byte values and results live in the
// verifier-known preprocessed table.

pub(crate) const COL_MULT_RANGE16: usize = eidos::NUM_RELATIONS;
pub const NUM_MAIN_COLS: usize = COL_MULT_RANGE16 + 1;
pub const NUM_AUX_COLS: usize = 4;
/// Width of the preprocessed table `[a, b, x, W12(x), W7(x)]`.
pub const NUM_PREPROCESSED_COLS: usize = 5;

/// Column indices into the preprocessed data table (see [`preprocessed_table`]).
pub const PRE_A: usize = 0;
pub const PRE_B: usize = 1;
pub const PRE_XOR: usize = 2;
pub const PRE_WRAP12: usize = 3;
pub const PRE_WRAP7: usize = 4;

/// Recover `a & b` from `x = a xor b` using `(a + b - x) / 2`.
#[cfg(test)]
pub(crate) fn and_result_from_xor<E: Algebra<Felt>>(a: E, b: E, x: E) -> E {
    (a + b - x).halve()
}

/// Recover `(!a) & b` from `x = a xor b` using `(x - a + b) / 2`.
///
/// The identity is linear, so it also holds when byte tuples are packed with common positional
/// weights, as in Keccak's 32-bit Memory64 limbs.
pub(crate) fn andnot_result_from_xor<E: Algebra<Felt>>(a: E, b: E, x: E) -> E {
    (x - a + b).halve()
}

/// Log2 of [`TRACE_HEIGHT`].
pub const LOG_TRACE_HEIGHT: u8 = 16;

/// Fixed trace height: every `(a, b) ∈ [0, 256)²` gets a row, in lex
/// order (`idx = (a << 8) | b`). The preprocessed data table
/// (`preprocessed_table`) is pinned to this lex enumeration on these
/// `2^16` rows; the seven witness multiplicity columns are committed in
/// lockstep at the same height.
pub const TRACE_HEIGHT: usize = 1 << LOG_TRACE_HEIGHT;

const NUM_BYTE_PAIRS: usize = TRACE_HEIGHT;

// PREPROCESSED TABLE
// ================================================================================================

/// The fixed `2^16 × 5` data table committed once as preprocessed
/// (verifier-known) columns: every `(a, b) ∈ [0, 256)²` in lex order
/// (`idx = (a << 8) | b`) with `x = a xor b` and the two wrapping Eidos rotation
/// contributions.
///
/// Column order matches [`PRE_A`], [`PRE_B`], [`PRE_XOR`], [`PRE_WRAP12`], and
/// [`PRE_WRAP7`]. Because the table is fixed and verifier-committed, its byte-pair, rotation, and
/// range-check relations are pinned to the correct values.
#[doc(hidden)]
pub fn preprocessed_table() -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(TRACE_HEIGHT * NUM_PREPROCESSED_COLS);
    for idx in 0..NUM_BYTE_PAIRS {
        let a = (idx >> 8) as u8;
        let b = (idx & 0xff) as u8;
        let x = a ^ b;
        values.extend([
            Felt::from(a),
            Felt::from(b),
            Felt::from(x),
            Felt::from(eidos::contribution(EidosRotation::Rot12, 1, a, b)),
            Felt::from(eidos::contribution(EidosRotation::Rot7, 0, a, b)),
        ]);
    }
    RowMajorMatrix::new(values, NUM_PREPROCESSED_COLS)
}

// MESSAGES
// ================================================================================================

/// Canonical byte-pair message `(a, b, x)`, where `x = a xor b`.
#[derive(Debug, Clone)]
pub struct BytePairLutMsg<E> {
    a: E,
    b: E,
    x: E,
}

impl<E: Algebra<Felt>> BytePairLutMsg<E> {
    /// Construct from an ordinary AND result.
    pub fn from_and(a: E, b: E, h: E) -> Self {
        let x = a.dup() + b.dup() - h.double();
        Self { a, b, x }
    }

    /// Construct from `c = (!a) & b` using `x = a - b + 2c`.
    pub fn from_andnot(a: E, b: E, c: E) -> Self {
        let x = a.dup() - b.dup() + c.double();
        Self { a, b, x }
    }
}

impl<E> BytePairLutMsg<E> {
    /// Construct from `x = a xor b` directly.
    pub fn from_xor(a: E, b: E, x: E) -> Self {
        Self { a, b, x }
    }
}

impl<E, EF> LookupMessage<E, EF> for BytePairLutMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges
            .encode(BusId::BytePairLut as usize, [self.a.clone(), self.b.clone(), self.x.clone()])
    }
}

/// Normalized Eidos rotation relation over a byte pair.
#[derive(Debug, Clone)]
struct EidosRotationMsg<E> {
    relation: EidosRelation,
    a: E,
    b: E,
    value: E,
}

impl<E> EidosRotationMsg<E> {
    fn from_normalized(relation: EidosRelation, a: E, b: E, value: E) -> Self {
        assert!(relation != EidosRelation::CanonicalXor);
        Self { relation, a, b, value }
    }
}

impl<E, EF> LookupMessage<E, EF> for EidosRotationMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            eidos::bus(self.relation) as usize,
            [self.a.clone(), self.b.clone(), self.value.clone()],
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

// LOOKUP AIR
// ================================================================================================

/// One accumulator interaction followed by three two-interaction fraction columns.
///
/// Keeping the singleton in column zero leaves the centered cyclic recurrence at degree two; the
/// remaining columns are degree three.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 2, 2];

impl<LB> lookup::LookupAir<LB> for BytePairLutAir
where
    LB: lookup::LookupBuilder<F = Felt>,
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

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let preprocessed = frame.preprocessed.current;
        let main = frame.main.current;

        let a_value = preprocessed[PRE_A].dup();
        let b_value = preprocessed[PRE_B].dup();
        let x = preprocessed[PRE_XOR].dup();
        let wrap12 = preprocessed[PRE_WRAP12].dup();
        let wrap7 = preprocessed[PRE_WRAP7].dup();
        let w = a_value.dup() + b_value.mul_2exp_u64(8);

        let neg_relation: [LB::Expr; eidos::NUM_RELATIONS] =
            core::array::from_fn(|relation| -main[relation].dup());
        let neg_range16 = -main[COL_MULT_RANGE16].dup();

        let relation_values = eidos::provider_values(x.clone(), wrap12, wrap7);

        let interaction_deg = Deg { v: 1, u: 1 };
        let pair_deg = Deg { v: 2, u: 2 };

        frac_col!(
            builder,
            "byte-pair-table",
            interaction_deg,
            (
                "canonical-xor",
                neg_relation[EidosRelation::CanonicalXor.index()].clone(),
                BytePairLutMsg::from_xor(a_value.clone(), b_value.clone(), x.clone()),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot12-pos1",
                neg_relation[EidosRelation::Rot12Pos1.index()].clone(),
                EidosRotationMsg::from_normalized(
                    EidosRelation::Rot12Pos1,
                    a_value.clone(),
                    b_value.clone(),
                    relation_values[EidosRelation::Rot12Pos1.index()].clone(),
                ),
                interaction_deg
            ),
            (
                "rot7-pos0",
                neg_relation[EidosRelation::Rot7Pos0.index()].clone(),
                EidosRotationMsg::from_normalized(
                    EidosRelation::Rot7Pos0,
                    a_value.clone(),
                    b_value.clone(),
                    relation_values[EidosRelation::Rot7Pos0.index()].clone(),
                ),
                interaction_deg
            ),
        );
        frac_col!(
            builder,
            "byte-pair-table",
            pair_deg,
            (
                "rot7-pos2",
                neg_relation[EidosRelation::Rot7Pos2.index()].clone(),
                EidosRotationMsg::from_normalized(
                    EidosRelation::Rot7Pos2,
                    a_value.clone(),
                    b_value.clone(),
                    relation_values[EidosRelation::Rot7Pos2.index()].clone(),
                ),
                interaction_deg
            ),
            (
                "rot12-pos3",
                neg_relation[EidosRelation::Rot12Pos3.index()].clone(),
                EidosRotationMsg::from_normalized(
                    EidosRelation::Rot12Pos3,
                    a_value.clone(),
                    b_value.clone(),
                    relation_values[EidosRelation::Rot12Pos3.index()].clone(),
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
                neg_relation[EidosRelation::Rot7Pos3.index()].clone(),
                EidosRotationMsg::from_normalized(
                    EidosRelation::Rot7Pos3,
                    a_value,
                    b_value,
                    relation_values[EidosRelation::Rot7Pos3.index()].clone(),
                ),
                interaction_deg
            ),
            ("range16", neg_range16, Range16Msg { w }, interaction_deg),
        );
    }
}

// PROVER
// ================================================================================================

impl air::LiftedAir for BytePairLutAir {
    type F = Felt;
    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: Some(air::PreprocessedSpec {
                width: NUM_PREPROCESSED_COLS,
                log_height: LOG_TRACE_HEIGHT,
            }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }
    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(preprocessed_table())
    }
    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for BytePairLutAir {
    type Error = lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn preprocessed_table_matches_the_mvm_byte_pair_table() {
        // Both verifiers commit to the same byte-pair matrix, including its column order.
        let mvm = crate::vm::and8_lookup::preprocessed_trace();
        let pvm = preprocessed_table();
        assert_eq!(mvm.width, pvm.width);
        assert_eq!(mvm.values, pvm.values);
    }

    #[test]
    fn affine_logic_reconstruction_matches_byte_operations() {
        for (a, b) in [(0u8, 0u8), (1, 2), (5, 3), (0xab, 0xcd), (255, 255)] {
            let a_felt = Felt::from(a);
            let b_felt = Felt::from(b);
            let x = Felt::from(a ^ b);

            assert_eq!(and_result_from_xor(a_felt, b_felt, x), Felt::from(a & b));
            assert_eq!(andnot_result_from_xor(a_felt, b_felt, x), Felt::from((!a) & b));
        }
    }

    #[test]
    fn andnot_reconstruction_commutes_with_packed_bytes() {
        let a = 0xf0_12_34_56u32;
        let b = 0xcc_ab_78_9au32;
        let x = a ^ b;
        assert_eq!(
            andnot_result_from_xor(Felt::from(a), Felt::from(b), Felt::from(x)),
            Felt::from((!a) & b),
        );
    }

    #[test]
    fn normalized_byte_pair_relations_are_domain_separated() {
        let challenges = Challenges::new(
            QuadFelt::from_u64(3),
            QuadFelt::from_u64(5),
            MAX_MESSAGE_WIDTH,
            NUM_BUS_IDS,
        );
        let a = Felt::from_u8(19);
        let b = Felt::from_u8(23);
        let x = Felt::from_u8(29);

        let encodings = [
            BytePairLutMsg::from_xor(a, b, x).encode(&challenges),
            EidosRotationMsg::from_normalized(EidosRelation::Rot12Pos1, a, b, x)
                .encode(&challenges),
            EidosRotationMsg::from_normalized(EidosRelation::Rot7Pos0, a, b, x).encode(&challenges),
            EidosRotationMsg::from_normalized(EidosRelation::Rot7Pos2, a, b, x).encode(&challenges),
            EidosRotationMsg::from_normalized(EidosRelation::Rot12Pos3, a, b, x)
                .encode(&challenges),
            EidosRotationMsg::from_normalized(EidosRelation::Rot7Pos3, a, b, x).encode(&challenges),
        ];

        for left in 0..encodings.len() {
            for right in left + 1..encodings.len() {
                assert_ne!(encodings[left], encodings[right]);
            }
        }
    }
    #[test]
    fn borrowed_byte_table_matches_slow_fractions_and_chiplet_dispatch() {
        let air = BytePairLutAir;
        let preprocessed = preprocessed_table();
        let main = RowMajorMatrix::new(
            (0..TRACE_HEIGHT * NUM_MAIN_COLS)
                .map(|i| Felt::from_usize(i % 17 + 1))
                .collect(),
            NUM_MAIN_COLS,
        );
        let challenges = [QuadFelt::new([Felt::from_u32(7), Felt::ONE]), QuadFelt::from_u32(13)];
        let inputs = air::AuxTraceInputs {
            main: &main,
            preprocessed: Some(&preprocessed),
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        };
        let borrowed = air::ProverAir::build_aux_trace(&air, inputs).unwrap();
        let encoding =
            Challenges::new(challenges[0], challenges[1], MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
        let fractions =
            lookup::build_lookup_fractions(&air, &main, Some(&preprocessed), &[], &encoding);
        let (expected, sigma) = miden_stark::lookup::accumulate_slow(&fractions);
        let (rows, remainder) = borrowed.columns.values.as_chunks::<NUM_AUX_COLS>();
        assert!(remainder.is_empty());
        for (row, values) in rows.iter().enumerate() {
            for (column, value) in values.iter().enumerate() {
                assert_eq!(*value, expected[column][row]);
            }
        }
        assert_eq!(borrowed.exports, [sigma]);
        let dispatched = air::ProverAir::build_aux_trace(
            &crate::precompiles::air::ChipletAir::BytePairLut,
            inputs,
        )
        .unwrap();
        assert_eq!(dispatched.columns.values, borrowed.columns.values);
        assert_eq!(dispatched.exports, borrowed.exports);
        assert!(
            air::ProverAir::build_aux_trace(
                &crate::precompiles::air::ChipletAir::BytePairLut,
                air::AuxTraceInputs { preprocessed: None, ..inputs }
            )
            .is_err(),
            "chiplet dispatch must reach the borrowed hook's setup validation"
        );
    }
}
