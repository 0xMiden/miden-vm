//! Native Eidos chaining chiplet for the deferred transcript.
//!
//! Each Eidos compression occupies one physical 32-row cycle. The controller accepts a block and,
//! at a fresh chain head, an initial chaining value. It returns the terminal chaining value bound
//! to the physical head and tail IDs of that chain.

pub mod compression;
pub mod digest;
pub mod messages;

use alloc::borrow::Cow;
use core::{array, borrow::Borrow};

use compression::{
    EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionCols,
    constraints::{enforce_footer_rows, enforce_fused_rows},
    emit_lookup_columns,
    layout::{
        BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_CYCLE_ID_COL, FOOTER_ROWS,
        NUM_COLS as NUM_EIDOS_COMPRESSION_COLS, footer_digest_col, footer_r_col,
    },
};
pub use digest::EidosDigest;
pub use messages::{EidosBlockMsg, EidosInitMsg, EidosOutMsg};
use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupColumn, LookupGroup, LookupMessage},
};
use p3_field::Dup;

use crate::{
    precompiles::{
        logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
        relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    },
    shared::eidos::{
        EidosCompressionSelectors, footer_cv_word, footer_message_word, get_periodic_column_values,
    },
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// The first 104 columns use the shared Eidos compression layout.
pub const COL_EIDOS_COMPRESSION_BEGIN: usize = 0;
pub const COL_EIDOS_COMPRESSION_END: usize = NUM_EIDOS_COMPRESSION_COLS;

/// Block-input multiplicity on footer 3, equal to the initial-CV multiplicity on footer 2.
pub const COL_IN_MULTIPLICITY: usize = 94;
/// Initial-CV multiplicity on footer 2. Footer 3 reuses this cell for output multiplicity.
pub const COL_INITIAL_MULTIPLICITY: usize = 64;
/// Terminal-digest multiplicity, stored only on footer row 3 in a free core cell.
pub const COL_OUT_MULTIPLICITY: usize = 64;
/// Incoming-link bit on footer 2. Footer 3 reuses this cell for the outgoing-link bit.
pub const COL_IS_CONTINUATION: usize = 96;
/// Outgoing-link bit on footer 3, matched to the next cycle by the continuation lookup.
pub const COL_HAS_SUCCESSOR: usize = 96;
/// Chain-head physical ID on footer 3, included in every continuation key and terminal output.
pub const COL_CHAIN_HEAD_ID: usize = 93;
/// The interface occupies footer cells in the shared compression layout.
pub const NUM_MAIN_COLS: usize = NUM_EIDOS_COMPRESSION_COLS;

// Block input, initial/terminal boundaries, and the predecessor-CV relation.
const PVM_AUX_COLS: usize = 3;
const EIDOS_COMPRESSION_AUX_COLS: usize = EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len();
const PVM_COLUMN_SHAPE: [usize; PVM_AUX_COLS] = [1, 1, 1];
const INTERFACE_AUX_BEGIN: usize = EIDOS_COMPRESSION_AUX_COLS;
const NUM_LOOKUP_COLS: usize = PVM_AUX_COLS + EIDOS_COMPRESSION_AUX_COLS;
const AUX_REGISTER_COL: usize = NUM_LOOKUP_COLS;
/// Number of auxiliary columns in the PVM Eidos compression AIR.
pub const NUM_AUX_COLS: usize = AUX_REGISTER_COL + 1;

const fn column_shape() -> [usize; NUM_LOOKUP_COLS] {
    let mut shape = [2; NUM_LOOKUP_COLS];
    let mut idx = 0;
    while idx < PVM_AUX_COLS {
        shape[INTERFACE_AUX_BEGIN + idx] = PVM_COLUMN_SHAPE[idx];
        idx += 1;
    }
    shape
}

const COLUMN_SHAPE: [usize; NUM_LOOKUP_COLS] = column_shape();

// PUBLIC AIR
// ================================================================================================

/// PVM-native Eidos compression AIR. One compression occupies exactly 32 rows.
#[derive(Debug, Default, Clone, Copy)]
pub struct EidosCompressionAir;

impl<LB> lookup::LookupAir<LB> for EidosCompressionAir
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
        {
            let local: &EidosCompressionCols<_> =
                frame.main.current[..NUM_EIDOS_COMPRESSION_COLS].borrow();
            let next: &EidosCompressionCols<_> =
                frame.main.next[..NUM_EIDOS_COMPRESSION_COLS].borrow();
            let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
            emit_lookup_columns(builder, local, next, &selectors);
        }
        <EidosCompressionInterfaceAir as lookup::LookupAir<LB>>::eval(
            &EidosCompressionInterfaceAir,
            frame,
            builder,
        );
    }
}

// PVM INTERFACE
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
#[doc(hidden)]
pub struct EidosCompressionInterfaceAir;

// PVM INTERFACE
// ================================================================================================

// The composed AIR's block denominator can vanish even at zero multiplicity. The two selected
// columns have denominator one outside their active rows and are pinned by their lookup equations.
fn enforce_inactive_block_aux<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
) {
    let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
    let inactive = AB::Expr::ONE - selectors.is_footer_row(3);
    let value = frame.aux.current[INTERFACE_AUX_BEGIN].dup();
    builder.assert_zero_ext(value * inactive);
}

fn enforce_interface_constraints<AB: air::LiftedAirBuilder<F = Felt>>(
    frame: &air::Frame<'_, AB>,
    builder: &mut AB,
) {
    let local = frame.main.current;
    let next = frame.main.next;
    let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
    let footer2 = selectors.is_footer_row(2);
    let footer3 = selectors.is_footer_row(3);
    let is_continuation: AB::Expr = local[COL_IS_CONTINUATION].dup();
    let compression_id: AB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].dup();
    // Each footer uses this core mode cell for its own link bit.
    builder
        .when(footer2.clone() + footer3)
        .assert_bool(local[COL_IS_CONTINUATION].dup());
    builder
        .when(footer2.clone())
        .assert_eq(local[COL_INITIAL_MULTIPLICITY].dup(), next[COL_IN_MULTIPLICITY].dup());

    // Continuation keys carry the head ID. Without an incoming link, the head is this cycle.
    // Canonical physical IDs leave no provider before cycle zero or consumer after the last
    // cycle, so exact link balance also closes both physical boundaries.
    builder.assert_zero(
        footer2
            * (AB::Expr::ONE - is_continuation)
            * (next[COL_CHAIN_HEAD_ID].dup() - compression_id),
    );

    // The initial-CV lookup uses footer 2. Bind its two additional CV words to footer 3,
    // where the compression core checks their byte representation and canonicality.
    for i in 6..8 {
        builder.when(selectors.is_footer_row(2)).assert_eq(
            footer_cv_word(|col| local[col].dup(), i),
            footer_cv_word(|col| next[col].dup(), i),
        );
    }
}

#[doc(hidden)]
pub const INTERNAL_CV_BUS_ID: usize = BusId::EidosCv as usize;

/// Initial CV of one continuation, matched to its predecessor by physical cycle and chain head.
#[derive(Debug)]
struct ContinuationCvMsg<E> {
    compression_cycle_id: E,
    chain_head_id: E,
    cv: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for ContinuationCvMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
        let [a, b, c, d] = self.cv.clone();
        challenges.encode(
            INTERNAL_CV_BUS_ID,
            [self.compression_cycle_id.clone(), self.chain_head_id.clone(), a, b, c, d],
        )
    }
}

impl<LB> lookup::LookupAir<LB> for EidosCompressionInterfaceAir
where
    LB: lookup::LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &PVM_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let local = frame.main.current;
        let next = frame.main.next;
        let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
        let footer3 = selectors.is_footer_row(FOOTER_ROWS - 1);

        let compression_id: LB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].dup();
        let in_mult: LB::Expr = local[COL_IN_MULTIPLICITY].dup();
        let initial_mult: LB::Expr = local[COL_INITIAL_MULTIPLICITY].dup();
        let out_mult: LB::Expr = local[COL_OUT_MULTIPLICITY].dup();
        let is_continuation: LB::Expr = local[COL_IS_CONTINUATION].dup();
        let has_successor: LB::Expr = local[COL_HAS_SUCCESSOR].dup();
        let chain_head_id: LB::Expr = local[COL_CHAIN_HEAD_ID].dup();
        let block = footer_block(|col| local[col].dup());
        let digest = array::from_fn(|idx| local[footer_digest_col(idx)].dup());
        let raw_cv = raw_cv_words(|col| local[col].dup());
        let initial_cv =
            array::from_fn(|idx| pack_pair(raw_cv[2 * idx].clone(), raw_cv[2 * idx + 1].clone()));

        let single_deg = Deg { v: 2, u: 1 };
        let boundary_deg = Deg { v: 3, u: 2 };
        let link_deg = Deg { v: 2, u: 2 };
        builder.next_column(
            |col| {
                col.group(
                    "block",
                    |group| {
                        group.insert(
                            "block",
                            LB::Expr::ONE,
                            -footer3.clone() * in_mult.clone(),
                            || EidosBlockMsg {
                                compression_id: compression_id.clone(),
                                block,
                            },
                            single_deg,
                        );
                    },
                    single_deg,
                )
            },
            single_deg,
        );
        // The two boundaries use distinct footer rows, so the selected denominator is linear
        // in each payload. Their gated degree-two multiplicities keep this column at degree 3.
        builder.next_column(
            |col| {
                col.group(
                    "boundaries",
                    |group| {
                        group.insert(
                            "initial-cv",
                            selectors.is_footer_row(2),
                            -initial_mult * (LB::Expr::ONE - is_continuation.clone()),
                            || EidosInitMsg {
                                compression_id: compression_id.clone(),
                                initial_cv: initial_cv.clone(),
                            },
                            boundary_deg,
                        );
                        group.insert(
                            "chain-output",
                            footer3.clone(),
                            -out_mult * (LB::Expr::ONE - has_successor.clone()),
                            || EidosOutMsg {
                                chain_head_id: chain_head_id.clone(),
                                compression_id: compression_id.clone(),
                                digest: digest.clone(),
                            },
                            boundary_deg,
                        );
                    },
                    boundary_deg,
                )
            },
            boundary_deg,
        );
        // Each active link has unit weight, independent of caller multiplicities. Its key binds
        // the physical successor, chain head and CV. Consumption and provision use distinct
        // footer rows, allowing one selected denominator at degree three.
        builder.next_column(
            |col| {
                col.group(
                    "continuation",
                    |group| {
                        group.insert(
                            "consume-cv",
                            selectors.is_footer_row(2),
                            -is_continuation,
                            || ContinuationCvMsg {
                                compression_cycle_id: compression_id.clone(),
                                chain_head_id: next[COL_CHAIN_HEAD_ID].dup(),
                                cv: initial_cv,
                            },
                            link_deg,
                        );
                        group.insert(
                            "provide-digest",
                            footer3,
                            has_successor,
                            || ContinuationCvMsg {
                                compression_cycle_id: compression_id + LB::Expr::ONE,
                                chain_head_id,
                                cv: digest,
                            },
                            link_deg,
                        );
                    },
                    link_deg,
                )
            },
            link_deg,
        );
    }
}

fn footer_block<E, A>(at: A) -> [E; 8]
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    array::from_fn(|idx| {
        if idx < 6 {
            at(footer_r_col(FOOTER_ROWS - 1, idx))
        } else {
            let pair = idx - 6;
            pack_pair(footer_message_word(&at, 2 * pair), footer_message_word(&at, 2 * pair + 1))
        }
    })
}

fn raw_cv_words<E, A>(at: A) -> [E; 8]
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    array::from_fn(|idx| footer_cv_word(&at, idx))
}

fn pack_pair<E: PrimeCharacteristicRing>(lo: E, hi: E) -> E {
    lo + E::from_u64(1u64 << 32) * hi
}

const _: () = assert!(EIDOS_COMPRESSION_CYCLE_LEN == 32);

impl air::LiftedAir for EidosCompressionAir {
    type F = Felt;
    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Owned(get_periodic_column_values()),
        }
    }
    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = &frame.main.current[..NUM_EIDOS_COMPRESSION_COLS];
        let next = &frame.main.next[..NUM_EIDOS_COMPRESSION_COLS];
        let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
        enforce_fused_rows(frame, builder, local, next, &selectors);
        enforce_footer_rows(frame, builder, local, next, &selectors);
        enforce_interface_constraints(frame, builder);
        enforce_inactive_block_aux(frame, builder);
        crate::shared::eidos::enforce_register_constraints(
            frame,
            inputs,
            builder,
            AUX_REGISTER_COL,
        );
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for EidosCompressionAir {
    type Error = crate::shared::eidos::EidosWitnessError;
    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        crate::shared::eidos::build_aux_trace(self, inputs, AUX_REGISTER_COL)
    }
}

impl air::LiftedAir for EidosCompressionInterfaceAir {
    type F = Felt;
    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: PVM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Owned(get_periodic_column_values()),
        }
    }
    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        enforce_interface_constraints(frame, builder);
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for EidosCompressionInterfaceAir {
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
    use alloc::{vec, vec::Vec};

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{
        air,
        lookup::{self, Challenges, LookupMessage},
    };

    use super::{
        ContinuationCvMsg, EidosBlockMsg, EidosCompressionAir, EidosCompressionInterfaceAir,
        EidosInitMsg, EidosOutMsg, INTERFACE_AUX_BEGIN, NUM_AUX_COLS, NUM_MAIN_COLS, PVM_AUX_COLS,
        compression::{
            layout::BLOCK_PERIOD, testing::generate_felt_trace_block_with_cycle_id,
            trace::set_cycle_metadata,
        },
        get_periodic_column_values,
    };
    use crate::precompiles::relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS};

    impl InterfaceConstraintEvalBuilder {
        fn eval_with(
            &mut self,
            evaluate: impl FnOnce(
                &air::AirFrame<'_, Felt, QuadFelt>,
                air::UniformInputs<'_, Felt, QuadFelt>,
                &mut NumericSink<'_>,
            ),
        ) {
            let width = self.main.width;
            let aux_width = self.aux.width;
            let frame = air::AirFrame {
                main: air::Rows {
                    current: &self.main.values[..width],
                    next: &self.main.values[width..2 * width],
                },
                preprocessed: air::Rows { current: &[], next: &[] },
                aux: air::Rows {
                    current: &self.aux.values[..aux_width],
                    next: &self.aux.values[aux_width..2 * aux_width],
                },
                periodic: &self.periodic_values,
                selectors: air::Selectors {
                    first: self.is_first_row,
                    last: self.is_last_row,
                    transition: Felt::ONE - self.is_last_row,
                },
            };
            let inputs = air::UniformInputs {
                public_values: &[],
                challenges: &self.randomness,
                exports: &self.permutation_values,
            };
            let mut sink = NumericSink {
                base: &mut self.base_evaluations,
                extension: &mut self.extension_evaluations,
            };
            evaluate(&frame, inputs, &mut sink);
        }
    }

    /// Numerical outputs are separate from the borrowed rows and uniform inputs.
    struct NumericSink<'a> {
        base: &'a mut Vec<Felt>,
        extension: &'a mut Vec<QuadFelt>,
    }

    impl air::LiftedAirBuilder for NumericSink<'_> {
        type F = Felt;
        type Expr = Felt;
        type ExtExpr = QuadFelt;
        fn emit_base(&mut self, value: Felt, _: air::ConstraintMeta<'_>) {
            self.base.push(value);
        }
        fn emit_ext(&mut self, value: QuadFelt, _: air::ConstraintMeta<'_>) {
            self.extension.push(value);
        }
    }

    struct InterfaceConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        base_evaluations: Vec<Felt>,
        extension_evaluations: Vec<QuadFelt>,

        is_first_row: Felt,
        is_last_row: Felt,
    }

    fn builder(row: usize, width: usize) -> InterfaceConstraintEvalBuilder {
        InterfaceConstraintEvalBuilder {
            main: RowMajorMatrix::new(vec![Felt::ZERO; 2 * NUM_MAIN_COLS], NUM_MAIN_COLS),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * width], width),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values: get_periodic_column_values()
                .iter()
                .map(|column| column[row])
                .collect(),
            base_evaluations: Vec::new(),
            extension_evaluations: Vec::new(),

            is_first_row: Felt::from_bool(row == 0),
            is_last_row: Felt::from_bool(row == BLOCK_PERIOD - 1),
        }
    }

    #[test]
    fn standalone_interface_accepts_nonzero_multiplicities() {
        let air = EidosCompressionInterfaceAir;
        let mut rows = generate_felt_trace_block_with_cycle_id([3; 16], [5; 8], 0).rows;
        set_cycle_metadata(
            rows.as_flattened_mut(),
            Felt::ONE,
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        );
        let main = RowMajorMatrix::new(rows.as_flattened().to_vec(), NUM_MAIN_COLS);
        let challenges =
            [QuadFelt::from_u32(7), QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)])];
        let air::AuxTrace { columns: aux, exports: sums } = air::ProverAir::build_aux_trace(
            &air,
            air::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        assert_ne!(sums[0], QuadFelt::ZERO);

        for row in 0..BLOCK_PERIOD {
            let next = (row + 1) % BLOCK_PERIOD;
            let mut builder = builder(row, PVM_AUX_COLS);
            builder.main.values = [rows[row], rows[next]].as_flattened().to_vec();
            builder.aux.values[..PVM_AUX_COLS]
                .copy_from_slice(&aux.values[row * PVM_AUX_COLS..(row + 1) * PVM_AUX_COLS]);
            builder.aux.values[PVM_AUX_COLS..]
                .copy_from_slice(&aux.values[next * PVM_AUX_COLS..(next + 1) * PVM_AUX_COLS]);
            builder.randomness = challenges.to_vec();
            builder.permutation_values = sums.clone();
            builder
                .eval_with(|frame, inputs, sink| air::LiftedAir::eval(&air, frame, inputs, sink));
            assert!(builder.base_evaluations.iter().all(|v| *v == Felt::ZERO), "row {row}");
            assert!(
                builder.extension_evaluations.iter().all(|v| *v == QuadFelt::ZERO),
                "row {row}"
            );
        }
    }

    #[test]
    fn inactive_interface_columns_are_pinned_even_with_zero_denominators() {
        // At alpha = beta = 0 all message denominators vanish. Both selected columns still have
        // denominator one outside their two active rows; only the block column needs a pin.
        let mut builder = builder(1, PVM_AUX_COLS);
        builder.aux.values[..PVM_AUX_COLS].fill(QuadFelt::ONE);
        let air = EidosCompressionInterfaceAir;
        builder.eval_with(|frame, inputs, sink| lookup::eval_lookup(&air, frame, inputs, sink));
        assert_eq!(
            builder.extension_evaluations,
            [QuadFelt::ZERO, QuadFelt::ZERO, QuadFelt::ONE, QuadFelt::ONE]
        );

        builder.extension_evaluations.clear();
        builder.aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * NUM_AUX_COLS], NUM_AUX_COLS);
        builder.aux.values[INTERFACE_AUX_BEGIN] = QuadFelt::ONE;
        builder.aux.values[INTERFACE_AUX_BEGIN + 2] = QuadFelt::ONE;
        builder.eval_with(|frame, inputs, sink| {
            air::LiftedAir::eval(&EidosCompressionAir, frame, inputs, sink)
        });
        assert_eq!(builder.extension_evaluations[0], QuadFelt::ONE);
        assert_eq!(builder.extension_evaluations.last(), Some(&QuadFelt::ONE));
    }

    #[test]
    fn internal_continuation_and_external_boundary_messages_have_distinct_domains() {
        let challenges = Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MAX_MESSAGE_WIDTH,
            NUM_BUS_IDS,
        );
        let encodings = [
            EidosBlockMsg {
                compression_id: Felt::ZERO,
                block: [Felt::ZERO; 8],
            }
            .encode(&challenges),
            ContinuationCvMsg {
                compression_cycle_id: Felt::ZERO,
                chain_head_id: Felt::ZERO,
                cv: [Felt::ZERO; 4],
            }
            .encode(&challenges),
            EidosInitMsg {
                compression_id: Felt::ZERO,
                initial_cv: [Felt::ZERO; 4],
            }
            .encode(&challenges),
            EidosOutMsg {
                chain_head_id: Felt::ZERO,
                compression_id: Felt::ZERO,
                digest: [Felt::ZERO; 4],
            }
            .encode(&challenges),
        ];
        for (i, encoding) in encodings.iter().enumerate() {
            assert!(!encodings[..i].contains(encoding));
        }
    }
}
