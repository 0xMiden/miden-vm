//! Native Eidos chaining chiplet for the deferred transcript.
//!
//! Each Eidos compression occupies one physical 32-row cycle. The controller accepts a block and,
//! at a fresh chain head, an initial chaining value. It returns the terminal chaining value bound
//! to the physical head and tail IDs of that chain.

pub mod compression;
pub mod digest;
pub mod messages;

use alloc::{borrow::Cow, vec, vec::Vec};
use core::{array, borrow::Borrow};

use compression::{
    EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionCols,
    NUM_PERIODIC_COLUMNS as EIDOS_COMPRESSION_PERIODIC_COLS,
    constraints::{enforce_footer_rows, enforce_fused_rows},
    emit_lookup_columns, get_periodic_column_values,
    layout::{
        BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_CYCLE_ID_COL, FOOTER_ROWS,
        NUM_COLS as NUM_EIDOS_COMPRESSION_COLS, footer_digest_col, footer_msg_word_col,
        footer_r_col,
    },
    selectors::EidosCompressionSelectors,
    universal_cv_word,
};
pub use digest::EidosDigest;
pub use messages::{EidosBlockMsg, EidosInitMsg, EidosOutMsg};
use miden_air::{
    logup::{BusId as MidenBusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        ConstraintLookupBuilder as MidenConstraintLookupBuilder, LookupAir,
        build_logup_aux_trace as build_miden_aux_trace,
    },
};
use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess};

use crate::{
    composite::{SubAirBuilder, concatenate_bands, extract_band},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, build_logup_aux_trace,
    },
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

/// Derives a symbolic packed initial CV from `(domain_tag, param0, param1, param2)`.
pub(crate) fn initial_cv_from_frame<E>(frame: [E; 4]) -> [E; 4]
where
    E: PrimeCharacteristicRing + From<Felt>,
{
    let base = Eidos::merkle_node_init_chaining_word().into_elements();
    array::from_fn(|idx| E::from(base[idx]) + frame[idx].clone())
}

// MAIN COLUMN LAYOUT
// ================================================================================================

/// The first 108 columns are the PVM-owned Eidos compression layout.
pub const COL_EIDOS_COMPRESSION_BEGIN: usize = 0;
pub const COL_EIDOS_COMPRESSION_END: usize = NUM_EIDOS_COMPRESSION_COLS;

/// Number of caller-side block and initial-CV messages consumed by this compression.
pub const COL_IN_MULTIPLICITY: usize = COL_EIDOS_COMPRESSION_END;
/// Number of caller-side terminal-digest messages consumed by this chain.
pub const COL_OUT_MULTIPLICITY: usize = COL_IN_MULTIPLICITY + 1;
/// Whether this compression continues the chain immediately before it.
pub const COL_IS_ABSORB: usize = COL_OUT_MULTIPLICITY + 1;
/// Physical compression ID of this chain's first cycle. Carried through continuations so the
/// terminal output binds both ends of the physical chain.
pub const COL_CHAIN_HEAD_ID: usize = COL_IS_ABSORB + 1;
/// Total PVM Eidos width: 108 compression columns and four interface columns.
pub const NUM_MAIN_COLS: usize = COL_CHAIN_HEAD_ID + 1;

// Block input, the internal full-CV bridge, and the initial/terminal boundary relation.
const PVM_AUX_COLS: usize = 3;
const EIDOS_COMPRESSION_AUX_COLS: usize = EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len();
/// Total PVM Eidos auxiliary width: 18 compression columns and three interface columns.
pub const NUM_AUX_COLS: usize = PVM_AUX_COLS + EIDOS_COMPRESSION_AUX_COLS;
const PVM_COLUMN_SHAPE: [usize; PVM_AUX_COLS] = [1, 1, 1];

const PVM_VALUE_OFFSET: usize = 0;
const EIDOS_COMPRESSION_VALUE_OFFSET: usize = 1;

// The two lookup families deliberately share alpha/beta but use different bus-prefix exponents:
// PVM prefixes sit at beta^18, while native Miden Eidos compression/And8 prefixes sit at beta^16.
// This keeps their denominator polynomials domain-separated even though both BusId enums start at
// zero. Equal widths would make cross-family bus-id collisions possible.
const _: () = assert!(MAX_MESSAGE_WIDTH != MIDEN_MAX_MESSAGE_WIDTH);

// PUBLIC AIR
// ================================================================================================

/// PVM-native Eidos compression AIR. One compression occupies exactly 32 rows.
#[derive(Debug, Default, Clone, Copy)]
pub struct EidosCompressionAir;

impl BaseAir<Felt> for EidosCompressionAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
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
        2
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let (pvm_aux, pvm_values) =
            EidosCompressionInterfaceAir.build_aux_trace(main, air_inputs, aux_inputs, challenges);
        let eidos_compression_main =
            extract_band(main, COL_EIDOS_COMPRESSION_BEGIN..COL_EIDOS_COMPRESSION_END);
        let (eidos_compression_aux, eidos_compression_values) = EidosCompressionNarrowAir
            .build_aux_trace(&eidos_compression_main, air_inputs, aux_inputs, challenges);
        assert_eq!(pvm_values.len(), 1);
        assert_eq!(eidos_compression_values.len(), 1);

        (
            concatenate_bands(&pvm_aux, &eidos_compression_aux),
            vec![pvm_values[0], eidos_compression_values[0]],
        )
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let mut interface = SubAirBuilder::new(
                builder,
                0..NUM_MAIN_COLS,
                0..0,
                0..PVM_AUX_COLS,
                PVM_VALUE_OFFSET..PVM_VALUE_OFFSET + 1,
                0..EIDOS_COMPRESSION_PERIODIC_COLS,
            );
            <EidosCompressionInterfaceAir as LiftedAir<Felt, QuadFelt>>::eval(
                &EidosCompressionInterfaceAir,
                &mut interface,
            );
        }
        {
            let mut compression = SubAirBuilder::new(
                builder,
                COL_EIDOS_COMPRESSION_BEGIN..COL_EIDOS_COMPRESSION_END,
                0..0,
                PVM_AUX_COLS..NUM_AUX_COLS,
                EIDOS_COMPRESSION_VALUE_OFFSET..EIDOS_COMPRESSION_VALUE_OFFSET + 1,
                0..EIDOS_COMPRESSION_PERIODIC_COLS,
            );
            <EidosCompressionNarrowAir as LiftedAir<Felt, QuadFelt>>::eval(
                &EidosCompressionNarrowAir,
                &mut compression,
            );
        }
    }
}

// EIDOS COMPRESSION CORE
// ================================================================================================

/// The intrinsic Eidos compression constraints and byte/range lookups, without Miden VM controller
/// or AEAD footer relations. The PVM interface below occupies those boundaries directly.
#[derive(Debug, Default, Clone, Copy)]
#[doc(hidden)]
pub struct EidosCompressionNarrowAir;

impl BaseAir<Felt> for EidosCompressionNarrowAir {
    fn width(&self) -> usize {
        NUM_EIDOS_COMPRESSION_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(get_periodic_column_values())
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionNarrowAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        EIDOS_COMPRESSION_AUX_COLS
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
        build_miden_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
        }

        let mut lb = MidenConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for EidosCompressionNarrowAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        EIDOS_COMPRESSION_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        MidenBusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &EidosCompressionCols<_> = main.current_slice().borrow();
        let next: &EidosCompressionCols<_> = main.next_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        emit_lookup_columns(builder, local, next, &selectors);
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

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
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
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periodic_values: Vec<AB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        let is_last = selectors.is_footer_row(3);
        let not_last = AB::Expr::ONE - is_last.clone();

        let is_absorb: AB::Expr = local[COL_IS_ABSORB].into();
        let is_absorb_next: AB::Expr = next[COL_IS_ABSORB].into();
        let compression_id: AB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].into();
        let chain_head_id: AB::Expr = local[COL_CHAIN_HEAD_ID].into();
        let chain_head_id_next: AB::Expr = next[COL_CHAIN_HEAD_ID].into();

        builder.assert_bool(local[COL_IS_ABSORB]);
        builder.when_first_row().assert_zero(is_absorb);

        // Every metadata column is constant throughout its physical 32-row compression cycle.
        for col in COL_IN_MULTIPLICITY..NUM_MAIN_COLS {
            builder.assert_zero(
                not_last.clone() * (AB::Expr::from(next[col]) - AB::Expr::from(local[col])),
            );
        }

        // A fresh chain starts at this physical compression. A continuation retains the head ID
        // from the preceding cycle. This binds terminal outputs to one contiguous native chain
        // without assigning any meaning to the caller's domain parameters.
        builder.assert_zero(
            selectors.is_first_fused()
                * (AB::Expr::ONE - AB::Expr::from(local[COL_IS_ABSORB]))
                * (chain_head_id.clone() - compression_id),
        );
        builder.when_transition().assert_zero(
            is_last.clone() * is_absorb_next.clone() * (chain_head_id_next - chain_head_id),
        );

        // A continuation starts from the preceding compression output. The primitive core already
        // constrains its physical cycle ID to be canonical and consecutive.
        for i in 0..4 {
            let next_cv = universal_cv_word(|col| AB::Expr::from(next[col]), 2 * i)
                + AB::Expr::from(Felt::new_unchecked(1u64 << 32))
                    * universal_cv_word(|col| AB::Expr::from(next[col]), 2 * i + 1);
            builder.when_transition().assert_zero(
                is_last.clone()
                    * is_absorb_next.clone()
                    * (next_cv - AB::Expr::from(local[footer_digest_col(i)])),
            );
        }

        let mut lb = CyclicConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

#[doc(hidden)]
pub const INTERNAL_CV_BUS_ID: usize = BusId::EidosCv as usize;

/// Cycle-tagged relation carrying all eight raw Eidos compression chaining-value words atomically.
///
/// This relation is internal to the interface AIR, but its ID lives in the shared PVM registry so
/// every prover, verifier, and diagnostic path constructs the same challenge table.
#[derive(Debug)]
struct FullCvMsg<E> {
    compression_cycle_id: E,
    words: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for FullCvMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
        let fields: [E; 9] = array::from_fn(|idx| {
            if idx == 0 {
                self.compression_cycle_id.clone()
            } else {
                self.words[idx - 1].clone()
            }
        });
        challenges.encode(INTERNAL_CV_BUS_ID, fields)
    }
}

impl<LB> LookupAir<LB> for EidosCompressionInterfaceAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        PVM_AUX_COLS
    }

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
        let first_fused = selectors.is_first_fused();
        let footer3 = selectors.is_footer_row(FOOTER_ROWS - 1);

        let compression_id: LB::Expr = local[F_COMPRESSION_CYCLE_ID_COL].into();
        let in_mult: LB::Expr = local[COL_IN_MULTIPLICITY].into();
        let out_mult: LB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let is_absorb: LB::Expr = local[COL_IS_ABSORB].into();
        let is_absorb_next: LB::Expr = next[COL_IS_ABSORB].into();
        let chain_head_id: LB::Expr = local[COL_CHAIN_HEAD_ID].into();
        let block = footer_block(|col| LB::Expr::from(local[col]));
        let digest = array::from_fn(|idx| local[footer_digest_col(idx)].into());
        let raw_cv = raw_cv_words(|col| LB::Expr::from(local[col]));
        let initial_cv =
            array::from_fn(|idx| pack_pair(raw_cv[2 * idx].clone(), raw_cv[2 * idx + 1].clone()));

        let linear = Deg { v: 1, u: 1 };
        let block_deg = Deg { v: 2, u: 1 };
        let cv_deg = Deg { v: 1, u: 2 };
        let boundary_deg = Deg { v: 3, u: 2 };

        // Keep the running-sum column's denominator linear. Its numerator selects the last row
        // and applies the cycle's input multiplicity.
        builder.next_column(
            |col| {
                col.group(
                    "eidos-compression-block",
                    |group| {
                        group.batch(
                            "block",
                            LB::Expr::ONE,
                            |batch| {
                                batch.insert(
                                    "block",
                                    -footer3.clone() * in_mult.clone(),
                                    EidosBlockMsg {
                                        compression_id: compression_id.clone(),
                                        block,
                                    },
                                    block_deg,
                                );
                            },
                            block_deg,
                        );
                    },
                    block_deg,
                );
            },
            block_deg,
        );

        // The internal relation carries all eight raw CV words from the first fused row to the
        // footer, where the primitive AIR has reconstructed and constrained them.
        builder.next_column(
            |col| {
                col.group(
                    "eidos-compression-cv",
                    |group| {
                        group.insert(
                            "consume-full-cv",
                            first_fused,
                            -LB::Expr::ONE,
                            || FullCvMsg {
                                compression_cycle_id: compression_id.clone(),
                                words: raw_cv.clone(),
                            },
                            linear,
                        );
                        group.insert(
                            "provide-full-cv",
                            footer3.clone(),
                            LB::Expr::ONE,
                            || FullCvMsg {
                                compression_cycle_id: compression_id.clone(),
                                words: raw_cv,
                            },
                            linear,
                        );
                    },
                    cv_deg,
                );
            },
            cv_deg,
        );

        // Initial CVs and terminal outputs occupy different rows, so this selected group contains
        // at most one denominator per row. The next-cycle continuation bit selects terminal rows.
        builder.next_column(
            |col| {
                col.group(
                    "eidos-compression-boundaries",
                    |group| {
                        group.insert(
                            "initial-cv",
                            selectors.is_first_fused(),
                            -in_mult * (LB::Expr::ONE - is_absorb),
                            || EidosInitMsg {
                                compression_id: compression_id.clone(),
                                initial_cv,
                            },
                            boundary_deg,
                        );
                        group.insert(
                            "chain-output",
                            footer3,
                            -out_mult * (LB::Expr::ONE - is_absorb_next),
                            || EidosOutMsg { chain_head_id, compression_id, digest },
                            boundary_deg,
                        );
                    },
                    boundary_deg,
                );
            },
            boundary_deg,
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
            pack_pair(at(footer_msg_word_col(2 * pair)), at(footer_msg_word_col(2 * pair + 1)))
        }
    })
}

fn raw_cv_words<E, A>(at: A) -> [E; 8]
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    array::from_fn(|idx| universal_cv_word(&at, idx))
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
        deferred::{DEFERRED_AND_FRAME, deferred_chunks_frame},
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_lifted_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};

    use super::{
        EidosCompressionInterfaceAir, EidosInitMsg, EidosOutMsg, FullCvMsg, NUM_MAIN_COLS,
        PVM_AUX_COLS, get_periodic_column_values, initial_cv_from_frame,
    };
    use crate::{
        logup::{Challenges, CyclicConstraintLookupBuilder, LookupAir, LookupMessage},
        relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    };

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

    #[test]
    fn symbolic_initial_cv_matches_typed_frames() {
        for frame in [DEFERRED_AND_FRAME, deferred_chunks_frame(3)] {
            assert_eq!(
                initial_cv_from_frame(frame.as_word().into_elements()),
                frame.initial_chaining_word().into_elements(),
            );
        }
    }

    #[test]
    fn inactive_interface_aux_columns_are_pinned_at_zero_denominators() {
        const INACTIVE_FUSED_ROW: usize = 1;

        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::ZERO,
            QuadFelt::ZERO,
            MAX_MESSAGE_WIDTH,
            NUM_BUS_IDS,
        );
        assert_eq!(
            [
                FullCvMsg {
                    compression_cycle_id: Felt::ZERO,
                    words: [Felt::ZERO; 8],
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
            ],
            [QuadFelt::ZERO; 3],
        );

        let periodic_values = get_periodic_column_values()
            .iter()
            .map(|column| column[INACTIVE_FUSED_ROW % column.len()])
            .collect();
        let mut aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * PVM_AUX_COLS], PVM_AUX_COLS);
        aux.values[1] = QuadFelt::ONE;
        aux.values[2] = QuadFelt::ONE;
        let mut builder = InterfaceConstraintEvalBuilder {
            main: RowMajorMatrix::new(vec![Felt::ZERO; 2 * NUM_MAIN_COLS], NUM_MAIN_COLS),
            aux,
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values,
            extension_evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
        };

        let air = EidosCompressionInterfaceAir;
        let mut lookup_builder = CyclicConstraintLookupBuilder::new(&mut builder, &air);
        LookupAir::eval(&air, &mut lookup_builder);

        // This all-zero row with alpha = beta = 0 makes both encoded interface denominators zero.
        // Because neither the first-fused nor footer-3 flag is active, each fraction constraint
        // must nevertheless reduce to `aux = 0`. Keeping the selectors in the flag argument is
        // what preserves the unit denominator on these inactive rows.
        assert_eq!(builder.extension_evaluations.len(), PVM_AUX_COLS + 2);
        assert_eq!(
            &builder.extension_evaluations[builder.extension_evaluations.len() - 2..],
            &[QuadFelt::ONE, QuadFelt::ONE],
        );
    }
}
