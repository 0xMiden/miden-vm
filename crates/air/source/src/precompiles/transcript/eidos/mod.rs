//! Native Eidos chaining chiplet for the deferred transcript.
//!
//! Each Eidos compression occupies one physical 32-row cycle. The controller accepts a block and,
//! at a fresh chain head, an initial chaining value. It returns the terminal chaining value bound
//! to the physical head and tail IDs of that chain.

pub mod compression;
pub mod digest;
pub mod messages;

use alloc::{borrow::Cow, vec::Vec};
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
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess},
    lookup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage, build_logup_aux_trace,
    },
};

use crate::{
    precompiles::{
        logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
        relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
        utils::{current_main, next_main},
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

impl BaseAir<Felt> for EidosCompressionAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(get_periodic_column_values())
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionAir {
    fn num_randomness(&self) -> usize {
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
        let (mut aux, sums) = miden_stark::lookup::build_logup_aux_trace_with_width(
            self,
            main,
            None,
            challenges,
            NUM_AUX_COLS,
        );
        crate::shared::eidos::fill_aux_register(main, &mut aux, AUX_REGISTER_COL, challenges[1]);
        (aux, sums)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = &main.current_slice()[..NUM_EIDOS_COMPRESSION_COLS];
            let next = &main.next_slice()[..NUM_EIDOS_COMPRESSION_COLS];
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
        }

        enforce_interface_constraints(builder);
        enforce_inactive_block_aux(builder, INTERFACE_AUX_BEGIN);
        crate::shared::eidos::enforce_register_constraints(builder, AUX_REGISTER_COL);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB> LookupAir<LB> for EidosCompressionAir
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
        {
            let main = builder.main();
            let local: &EidosCompressionCols<_> =
                main.current_slice()[..NUM_EIDOS_COMPRESSION_COLS].borrow();
            let next: &EidosCompressionCols<_> =
                main.next_slice()[..NUM_EIDOS_COMPRESSION_COLS].borrow();
            let periodic_values: Vec<LB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
            emit_lookup_columns(builder, local, next, &selectors);
        }
        <EidosCompressionInterfaceAir as LookupAir<LB>>::eval(
            &EidosCompressionInterfaceAir,
            builder,
        );
    }
}

// PVM INTERFACE
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
#[doc(hidden)]
pub struct EidosCompressionInterfaceAir;

impl BaseAir<Felt> for EidosCompressionInterfaceAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(get_periodic_column_values())
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionInterfaceAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        PVM_AUX_COLS
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
        build_logup_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        enforce_interface_constraints(builder);
        enforce_inactive_block_aux(builder, 0);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

// PVM INTERFACE
// ================================================================================================

// The block denominator can vanish even at zero multiplicity. The two selected columns
// have denominator one outside their active rows and are pinned by their lookup equations.
fn enforce_inactive_block_aux<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, offset: usize) {
    let periodic: Vec<AB::Expr> = builder.periodic_values().iter().map(|&v| v.into()).collect();
    let selectors = EidosCompressionSelectors::new(&periodic, 0);
    let inactive = AB::Expr::ONE - selectors.is_footer_row(3);
    let aux = builder.permutation();
    let value: AB::ExprEF = aux.current_slice()[offset].into();
    builder.assert_zero_ext(value * inactive);
}

fn enforce_interface_constraints<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
    let periodic_values: Vec<AB::Expr> =
        builder.periodic_values().iter().map(|value| (*value).into()).collect();
    let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
    let footer2 = selectors.is_footer_row(2);
    let footer3 = selectors.is_footer_row(3);
    let is_continuation: AB::Expr = local[COL_IS_CONTINUATION].into();
    let compression_id: AB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].into();
    // Each footer uses this core mode cell for its own link bit.
    builder.when(footer2.clone() + footer3).assert_bool(local[COL_IS_CONTINUATION]);
    builder
        .when(footer2.clone())
        .assert_eq(local[COL_INITIAL_MULTIPLICITY], next[COL_IN_MULTIPLICITY]);

    // Continuation keys carry the head ID. Without an incoming link, the head is this cycle.
    // Canonical physical IDs leave no provider before cycle zero or consumer after the last
    // cycle, so exact link balance also closes both physical boundaries.
    builder.assert_zero(
        footer2
            * (AB::Expr::ONE - is_continuation)
            * (AB::Expr::from(next[COL_CHAIN_HEAD_ID]) - compression_id),
    );

    // The initial-CV lookup uses footer 2. Bind its two additional CV words to footer 3,
    // where the compression core checks their byte representation and canonicality.
    for i in 6..8 {
        builder.when(selectors.is_footer_row(2)).assert_eq(
            footer_cv_word(|col| AB::Expr::from(local[col]), i),
            footer_cv_word(|col| AB::Expr::from(next[col]), i),
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

impl<LB> LookupAir<LB> for EidosCompressionInterfaceAir
where
    LB: LookupBuilder<F = Felt>,
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

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        let footer3 = selectors.is_footer_row(FOOTER_ROWS - 1);

        let compression_id: LB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].into();
        let in_mult: LB::Expr = local[COL_IN_MULTIPLICITY].into();
        let initial_mult: LB::Expr = local[COL_INITIAL_MULTIPLICITY].into();
        let out_mult: LB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let is_continuation: LB::Expr = local[COL_IS_CONTINUATION].into();
        let has_successor: LB::Expr = local[COL_HAS_SUCCESSOR].into();
        let chain_head_id: LB::Expr = local[COL_CHAIN_HEAD_ID].into();
        let block = footer_block(|col| LB::Expr::from(local[col]));
        let digest = array::from_fn(|idx| local[footer_digest_col(idx)].into());
        let raw_cv = raw_cv_words(|col| LB::Expr::from(local[col]));
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
                                chain_head_id: next[COL_CHAIN_HEAD_ID].into(),
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

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{
        air::{AirBuilder, ExtensionBuilder, LiftedAir, PermutationAirBuilder, RowWindow},
        lookup::{Challenges, ConstraintLookupBuilder, LookupAir, LookupMessage},
    };

    use super::{
        ContinuationCvMsg, EidosBlockMsg, EidosCompressionAir, EidosCompressionInterfaceAir,
        EidosInitMsg, EidosOutMsg, INTERFACE_AUX_BEGIN, NUM_AUX_COLS, NUM_MAIN_COLS, PVM_AUX_COLS,
        get_periodic_column_values,
    };
    use crate::precompiles::relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS};

    struct InterfaceConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        extension_evaluations: Vec<QuadFelt>,
        preprocessed_window: RowWindow<'static, Felt>,
    }

    impl AirBuilder for InterfaceConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;
        type PeriodicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed_window
        }

        fn is_first_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "PVM Eidos interface tests use two-row transition windows");
            Felt::ONE
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, _value: I) {}

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
        }

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    impl ExtensionBuilder for InterfaceConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, value: I) {
            self.extension_evaluations.push(value.into());
        }
    }

    impl PermutationAirBuilder for InterfaceConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
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
            extension_evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
        }
    }

    #[test]
    fn inactive_interface_columns_are_pinned_even_with_zero_denominators() {
        // At alpha = beta = 0 all message denominators vanish. Both selected columns still have
        // denominator one outside their two active rows; only the block column needs a pin.
        let mut builder = builder(1, PVM_AUX_COLS);
        builder.aux.values[..PVM_AUX_COLS].fill(QuadFelt::ONE);
        let air = EidosCompressionInterfaceAir;
        let mut lookup_builder = ConstraintLookupBuilder::new(&mut builder, &air);
        LookupAir::eval(&air, &mut lookup_builder);
        lookup_builder.finish();
        assert_eq!(
            builder.extension_evaluations,
            [QuadFelt::ZERO, QuadFelt::ZERO, QuadFelt::ONE, QuadFelt::ONE]
        );

        builder.extension_evaluations.clear();
        builder.aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * NUM_AUX_COLS], NUM_AUX_COLS);
        builder.aux.values[INTERFACE_AUX_BEGIN] = QuadFelt::ONE;
        builder.aux.values[INTERFACE_AUX_BEGIN + 2] = QuadFelt::ONE;
        <EidosCompressionAir as LiftedAir<Felt, QuadFelt>>::eval(
            &EidosCompressionAir,
            &mut builder,
        );
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
